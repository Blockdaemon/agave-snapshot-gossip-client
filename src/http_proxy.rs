use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use jsonrpc_core::futures::{future, FutureExt};
use jsonrpc_http_server::{
    hyper::{
        self,
        client::{connect::Connect, HttpConnector},
        header::{self, HeaderName},
        Body, Client, Request, Response, StatusCode, Uri,
    },
    RequestMiddlewareAction,
};
use log::{debug, error};
use rustls::RootCertStore;
use rustls_native_certs;

// Function to create the HTTPS-capable hyper client using rustls
pub fn create_proxy_client() -> Client<HttpsConnector<HttpConnector>> {
    // Load native certs
    let mut root_cert_store = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        let _ = root_cert_store.add(cert);
    }

    // Build HttpsConnector using the rustls config and http connector
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);

    Client::builder().build(https)
}

// Helper to create a simple status code response
pub fn respond_with_status(status_code: StatusCode) -> RequestMiddlewareAction {
    let response = Response::builder()
        .status(status_code)
        .body(Body::empty())
        .unwrap(); // Safe unwrap: status code is valid
    RequestMiddlewareAction::Respond {
        response: Box::pin(future::ok(response)),
        should_validate_hosts: true,
    }
}

// Builds the outgoing request for the reverse proxy
pub fn build_proxy_request(
    incoming_request: &Request<Body>,
    target_uri: Uri,
) -> Result<Request<Body>, String> {
    let mut proxy_req_builder = Request::builder()
        .method(incoming_request.method().clone())
        .uri(target_uri)
        .version(incoming_request.version());

    // Clone headers, potentially filtering/modifying
    for (key, value) in incoming_request.headers() {
        // Don't copy the original host header
        if key != header::HOST {
            proxy_req_builder = proxy_req_builder.header(key.clone(), value.clone());
        }
    }

    // Add X-Forwarded-For header using from_static
    let forwarded_for_header_name = HeaderName::from_static("x-forwarded-for");
    let forwarded_for_value = match incoming_request.headers().get(&forwarded_for_header_name) {
        Some(existing) => format!("{}, unknown", existing.to_str().unwrap_or("")),
        None => "unknown".to_string(),
    };
    proxy_req_builder = proxy_req_builder.header(forwarded_for_header_name, forwarded_for_value);

    // Add X-Forwarded-Proto using from_static
    let forwarded_proto_header_name = HeaderName::from_static("x-forwarded-proto");
    proxy_req_builder = proxy_req_builder.header(forwarded_proto_header_name, "http");

    // Build the request with an empty body for GET
    proxy_req_builder
        .body(Body::empty()) // Assuming GET, might need body for other methods
        .map_err(|e| format!("Failed to build proxy request: {}", e))
}

// Handles the logic for parsing the target URI, building, and executing the proxy request
pub fn handle_proxy_request<C>(
    client: Client<C>,
    request: Request<Body>,
    target_url_str: String,
) -> RequestMiddlewareAction
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let target_uri = match target_url_str.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => {
            error!("Failed to parse target URI '{}': {}", target_url_str, e);
            return respond_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let proxy_req = match build_proxy_request(&request, target_uri) {
        Ok(req) => req,
        Err(e) => {
            error!("{}", e);
            return respond_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // --> Add logging here <--
    debug!(
        "Attempting proxy request to URI: scheme={:?}, authority={:?}, path={}",
        proxy_req.uri().scheme(),
        proxy_req.uri().authority(),
        proxy_req.uri().path()
    );

    // Make the request and handle potential errors internally
    let response_future = async move {
        match client.request(proxy_req).await {
            Ok(res) => Ok(res), // Pass through successful response
            Err(e) => {
                // Log the failure and create a 502 Bad Gateway response
                error!("Proxy request failed: {}", e);
                // Return Ok containing the error response. The outer Result represents
                // the success/failure of the *future's execution*, not the HTTP request.
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::empty())
                    .unwrap()) // Safe unwrap: builder components are valid
            }
        }
    }
    // Ensure the final future output matches the expected type signature for the middleware.
    .map(|internal_result: Result<Response<Body>, hyper::Error>| -> Result<Response<Body>, hyper::Error> {
        match internal_result {
            Ok(response) => Ok(response),
            Err(_) => unreachable!("Error should have been handled inside the async block"),
        }
    })
    .boxed();

    RequestMiddlewareAction::Respond {
        response: response_future,
        should_validate_hosts: true, // Keep host validation?
    }
}

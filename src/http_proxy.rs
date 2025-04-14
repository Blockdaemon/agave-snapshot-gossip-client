use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use jsonrpc_http_server::hyper::{
    self,
    client::{connect::Connect, HttpConnector},
    header::{self, HeaderName},
    Body, Client, Request, Response, StatusCode, Uri,
};
use log::{debug, error};

// Function to create the HTTPS-capable hyper client using rustls
pub fn create_proxy_client() -> Client<HttpsConnector<HttpConnector>> {
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

// Helper to create a simple status code response for direct use
fn create_error_response(status_code: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status_code)
        .body(Body::empty())
        .unwrap() // Safe unwrap: status code is valid
}

// Builds the outgoing request for the reverse proxy
fn build_proxy_request(
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
pub async fn handle_proxy_request<C>(
    client: Client<C>,
    request: Request<Body>,
    target_uri: Uri,
) -> Result<Response<Body>, hyper::Error>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let proxy_req = match build_proxy_request(&request, target_uri) {
        Ok(req) => req,
        Err(e) => {
            error!("{}", e);
            return Ok(create_error_response(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    debug!(
        "Attempting proxy request to URI: scheme={:?}, authority={:?}, path={}",
        proxy_req.uri().scheme(),
        proxy_req.uri().authority(),
        proxy_req.uri().path()
    );

    client.request(proxy_req).await
}

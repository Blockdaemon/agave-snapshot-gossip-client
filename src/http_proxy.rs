// Simple HTTP proxy for Axum
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode, Uri},
};
use log::{info, warn};
use reqwest::Client;

// Create a proxy client with HTTPS support
pub fn create_proxy_client() -> Client {
    reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true) // For development only
        .build()
        .expect("Failed to create HTTP client")
}

// Fully functional proxy handler for Axum
pub async fn proxy_to(target_uri: Uri, req: Request<Body>) -> Response<Body> {
    info!("Proxying to {}", target_uri);

    // Create client
    let client = create_proxy_client();

    // Build request based on method
    let mut request_builder = match req.method() {
        &http::Method::GET => client.get(target_uri.to_string()),
        &http::Method::POST => client.post(target_uri.to_string()),
        &http::Method::PUT => client.put(target_uri.to_string()),
        &http::Method::DELETE => client.delete(target_uri.to_string()),
        &http::Method::HEAD => client.head(target_uri.to_string()),
        &http::Method::OPTIONS => client.request(reqwest::Method::OPTIONS, target_uri.to_string()),
        &http::Method::PATCH => client.patch(target_uri.to_string()),
        _ => {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Method not allowed for proxying"))
                .unwrap();
        }
    };

    // Copy headers from original request
    for (name, value) in req.headers() {
        // Skip host header as it will be set by reqwest
        if name != header::HOST {
            request_builder = request_builder.header(name.clone(), value.clone());
        }
    }

    // Add proxy headers
    request_builder = request_builder
        .header("X-Forwarded-Proto", "http")
        .header("X-Forwarded-For", "unknown");

    // For non-GET requests, handle request body (snapshots use GET so this is simple for now)
    if req.method() != http::Method::GET && req.method() != http::Method::HEAD {
        // If needed in the future, handle request body here
    }

    // Execute the request
    let proxy_response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Proxy request failed: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Proxy error: {}", e)))
                .unwrap();
        }
    };

    // Build the response from the proxied response
    let status = proxy_response.status();
    let proxy_headers = proxy_response.headers().clone();

    // Get the response body
    let bytes = match proxy_response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to read proxy response body: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Failed to read upstream response"))
                .unwrap();
        }
    };

    // Create the response with the status code
    let mut response_builder = Response::builder().status(status);

    // Copy the headers from the proxied response
    for (name, value) in proxy_headers.iter() {
        response_builder = response_builder.header(name, value);
    }

    // Add a header indicating this was proxied
    response_builder = response_builder.header("X-Proxy-Server", "Agave-Snapshot-Proxy");

    // Build the response with the body
    match response_builder.body(Body::from(bytes)) {
        Ok(response) => response,
        Err(e) => {
            warn!("Failed to build response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to build response"))
                .unwrap()
        }
    }
}

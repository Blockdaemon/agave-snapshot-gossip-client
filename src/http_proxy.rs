// Simple HTTP proxy for Axum
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode, Uri},
};
use log::{debug, warn};
use reqwest::Client;
use std::time::Duration;

use crate::constants::{PROXY_REQUEST_TIMEOUT_SECS, SOLANA_VALIDATOR_USER_AGENT};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(PROXY_REQUEST_TIMEOUT_SECS);

// Create a proxy client with HTTPS support
pub fn create_proxy_client() -> Client {
    reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true) // For development only
        .user_agent(SOLANA_VALIDATOR_USER_AGENT)
        .timeout(REQUEST_TIMEOUT) // Add explicit request timeout
        .build()
        .expect("Failed to create HTTP client")
}

// Fully functional proxy handler for Axum
// Takes the target_uri and replaces the path with the path from the original request
pub async fn proxy_to(target_uri: Uri, req: Request<Body>) -> Response<Body> {
    debug!("target URI: {}", target_uri);
    // Create client
    let client = create_proxy_client();

    // Get the base URI from the target_uri by not including the path
    let base_uri = format!(
        "{}://{}",
        target_uri.scheme().unwrap(),
        target_uri.authority().unwrap()
    );
    debug!("Base URI: {}", base_uri);

    // Get only the path from the original request
    let path = req.uri().path();
    debug!("Path: {}", path);

    // Build request based on method
    let mut request_builder = match *req.method() {
        http::Method::GET => client.get(format!("{}{}", base_uri, path)),
        http::Method::POST => client.post(format!("{}{}", base_uri, path)),
        http::Method::PUT => client.put(format!("{}{}", base_uri, path)),
        http::Method::DELETE => client.delete(format!("{}{}", base_uri, path)),
        http::Method::HEAD => client.head(format!("{}{}", base_uri, path)),
        http::Method::OPTIONS => {
            client.request(reqwest::Method::OPTIONS, format!("{}{}", base_uri, path))
        }
        http::Method::PATCH => client.patch(format!("{}{}", base_uri, path)),
        _ => {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Method not allowed for proxying\n"))
                .unwrap();
        }
    };

    // Copy headers from original request
    for (name, value) in req.headers() {
        // Skip host and user-agent headers as they will be set by reqwest
        if name != header::HOST && name != header::USER_AGENT {
            request_builder = request_builder.header(name.clone(), value.clone());
        }
    }

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
                .body(Body::from(format!("Proxy error: {}\n", e)))
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
                .body(Body::from("Failed to read upstream response\n"))
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
                .body(Body::from("Failed to build response\n"))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Method;
    use axum::http::Request;
    use env_logger;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_proxy_user_agent() {
        // Initialize test logger
        let _ = env_logger::try_init();

        // Start a mock server
        let mock_server = MockServer::start().await;

        // Set up the mock to expect a request with our user agent
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/test"))
            .and(wiremock::matchers::header(
                "User-Agent",
                SOLANA_VALIDATOR_USER_AGENT,
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create a test request
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("{}/test", mock_server.uri()))
            .header(header::USER_AGENT, "unknown") // set a "bad" user-agent to test that it is overridden
            .body(Body::empty())
            .unwrap();

        // Create a test URI (just the base URI)
        let target_uri = mock_server.uri().parse::<Uri>().unwrap();

        // Call the proxy function
        let response = proxy_to(target_uri, req).await;

        // Print path and headers from received requests
        let user_agent = wiremock::http::HeaderName::from_bytes(b"user-agent").unwrap();
        let received_requests = mock_server
            .received_requests()
            .await
            .expect("No requests received");
        for request in received_requests {
            println!("Request path {}", request.url.path());
            println!(
                "Request user-agent: {}",
                request.headers.get(&user_agent).unwrap().to_str().unwrap()
            );
        }

        // The response should be successful
        assert_eq!(response.status(), StatusCode::OK);
    }
}

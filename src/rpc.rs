use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{header, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use log::{error, info, warn};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;

// Our local crates
use crate::atomic_state::AtomicState;
use crate::constants::SNAPSHOT_REGEX;
use crate::healthcheck;
use crate::http_proxy;
use crate::local_storage;
use crate::scraper::MetadataScraper;

// Helper function to extract client IP from the request
fn get_client_ip(req: &Request<Body>) -> String {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// Helper function to extract user agent from the request
fn get_user_agent(req: &Request<Body>) -> String {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

// Helper function to create a JSON-RPC response
fn jsonrpc_response(result: Value, id: Option<Value>, status_code: StatusCode) -> Response {
    let id = id.unwrap_or(Value::Null);
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        json!({ "jsonrpc": "2.0", "result": result, "id": id }).to_string() + "\n",
    )
        .into_response()
}

// Helper function to create a JSON-RPC error response
fn jsonrpc_error(code: i32, message: &str, id: Option<Value>, status_code: StatusCode) -> Response {
    let id = id.unwrap_or(Value::Null);
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        json!({ "jsonrpc": "2.0", "error": { "code": code, "message": message, }, "id": id })
            .to_string()
            + "\n",
    )
        .into_response()
}

#[derive(Clone)]
pub struct AppState {
    scraper: Arc<MetadataScraper>,
    atomic_state: AtomicState,
    enable_proxy: bool,
    serve_local: bool,
}

pub struct RpcServer {
    scraper: Arc<MetadataScraper>,
    atomic_state: AtomicState,
    enable_proxy: bool,
}

impl RpcServer {
    pub fn new(
        scraper: Arc<MetadataScraper>,
        atomic_state: AtomicState,
        enable_proxy: bool,
    ) -> Self {
        Self {
            scraper,
            atomic_state,
            enable_proxy,
        }
    }

    // This handler routes GET requests based on the path
    async fn handle_get_request(State(state): State<AppState>, req: Request<Body>) -> Response {
        let client_ip = get_client_ip(&req);
        let user_agent = get_user_agent(&req);
        info!(
            "GET request from {} with user agent: {}",
            client_ip, user_agent
        );

        let path = req.uri().path();

        if SNAPSHOT_REGEX.is_match(path) {
            Self::handle_snapshot_request(State(state), req)
                .await
                .into_response()
        } else {
            let peer_ip = get_client_ip(&req);
            warn!(
                "Returning 404 for non-matching GET request: {} from {}",
                path, peer_ip
            );
            (StatusCode::NOT_FOUND, "Not Found\n").into_response()
        }
    }

    async fn handle_snapshot_request(
        State(state): State<AppState>,
        req: Request<Body>,
    ) -> impl IntoResponse {
        let path = req.uri().path().to_string();
        let peer_ip = get_client_ip(&req);
        info!(
            "{} request from {} for path: {}",
            req.method(),
            peer_ip,
            path
        );

        let uri = match Uri::builder().path_and_query(&path).build() {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to build URI for {}: {}", peer_ip, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n")
                    .into_response();
            }
        };

        match state.scraper.build_uri(&uri).await {
            Ok(target_uri) => {
                if state.serve_local {
                    info!("Serving local file for {}: {}", peer_ip, path);
                    let local_path = state.scraper.storage_path().unwrap().path().to_string();
                    // Use the local_storage module to serve the file
                    local_storage::LocalStorage::handle_request(
                        State(local_storage::LocalStorage::new(local_path)),
                        Path(path),
                    )
                    .await
                    .into_response()
                } else if state.enable_proxy {
                    info!(
                        "Proxying snapshot request for {} to {}",
                        peer_ip, target_uri
                    );

                    // Use the http_proxy module's proxy_to function
                    http_proxy::proxy_to(target_uri, req).await
                } else {
                    info!(
                        "Redirecting snapshot request for {} to {}",
                        peer_ip, target_uri
                    );

                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(header::LOCATION, target_uri.to_string())
                        .body(Body::empty())
                        .unwrap()
                        .into_response()
                }
            }
            Err(e) => {
                error!("Failed to build URI for {}: {}", peer_ip, e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build URI\n").into_response()
            }
        }
    }

    async fn handle_rpc_request(
        State(state): State<AppState>,
        req: Request<Body>,
    ) -> impl IntoResponse {
        let client_ip = get_client_ip(&req);
        let user_agent = get_user_agent(&req);
        info!(
            "RPC request from {} with user agent: {}",
            client_ip, user_agent
        );

        // Only handle POST requests for JSON-RPC
        if req.method() != Method::POST {
            return (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n").into_response();
        }

        let peer_ip = get_client_ip(&req);

        // Extract the JSON payload
        let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return (StatusCode::BAD_REQUEST, "Bad request\n").into_response();
            }
        };

        // Parse the JSON-RPC request
        let rpc_req: Value = match serde_json::from_slice(&body_bytes) {
            Ok(val) => val,
            Err(e) => {
                error!("Failed to parse JSON-RPC request: {}", e);
                return (StatusCode::BAD_REQUEST, "Invalid JSON\n").into_response();
            }
        };

        // Extract the method and handle accordingly
        let method = match rpc_req.get("method").and_then(|m| m.as_str()) {
            Some(m) => m,
            None => {
                let id = rpc_req.get("id").map(|v| v.clone());
                return jsonrpc_error(-32600, "Invalid request", id, StatusCode::BAD_REQUEST);
            }
        };

        info!("Processing RPC method: {} from {}", method, peer_ip);

        let id = rpc_req.get("id").map(|v| v.clone());

        // Handle different RPC methods
        let result = match method {
            // standard solana methods
            "getVersion" => {
                let info = state.scraper.get_cached_snapshot_info().await;
                json!(RpcVersionInfo {
                    solana_core: info.solana_version,
                    feature_set: info.solana_feature_set,
                })
            }
            "getGenesisHash" => {
                let state = state.scraper.get_cached_snapshot_info().await;
                json!(state.genesis_hash)
            }
            "getSlot" => {
                let state = state.scraper.get_cached_snapshot_info().await;
                json!(state.slot)
            }
            // our own non-standard methods
            "getNumPeers" => {
                json!(state.atomic_state.get_num_peers())
            }
            "getShredVersion" => {
                json!(state.atomic_state.get_shred_version())
            }
            "getPublicKey" => {
                json!(state.atomic_state.get_pubkey())
            }
            _ => {
                return jsonrpc_error(-32601, "Method not found", id, StatusCode::BAD_REQUEST);
            }
        };

        // Return the JSON-RPC response
        jsonrpc_response(result, id, StatusCode::OK)
    }

    pub async fn start(self, addr: SocketAddr, exit: Arc<AtomicBool>) -> Result<(), anyhow::Error> {
        info!("Starting RPC server on {}", addr);

        // Create the application state
        let app_state = AppState {
            scraper: self.scraper.clone(),
            atomic_state: self.atomic_state.clone(),
            enable_proxy: self.enable_proxy,
            serve_local: self
                .scraper
                .storage_path()
                .map(|uri| uri.scheme_str() == Some("file"))
                .unwrap_or(false),
        };

        // Create our application router with routes
        let app = Router::new()
            .route("/", axum::routing::post(Self::handle_rpc_request))
            .route("/{*path}", axum::routing::get(Self::handle_get_request))
            .fallback(|req: Request<Body>| async move {
                // Handle non-GET/POST methods with 405
                let path = req.uri().path();
                let peer_ip = get_client_ip(&req);
                warn!(
                    "Returning 405 for {} request: {} from {}",
                    req.method(),
                    path,
                    peer_ip
                );
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::from("Method Not Allowed\n"))
                    .unwrap()
            })
            .with_state(app_state);

        // Add health check route
        let app = healthcheck::add_health_check_route(app);

        // Create the TCP listener
        let listener = TcpListener::bind(addr).await?;
        info!("Listener bound to {}", addr);

        // Spawn the server in the background, checking exit flag periodically
        tokio::spawn(async move {
            info!("Server started on {}", addr);

            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            );

            // Run the server with a check for the exit signal
            tokio::select! {
                result = server => {
                    if let Err(e) = result {
                        error!("Server error: {}", e);
                    }
                },
                _ = async {
                    while !exit.load(std::sync::atomic::Ordering::Relaxed) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } => {
                    info!("Exit signal received, shutting down server");
                }
            }

            info!("Server shutdown complete");
        });

        info!("RPC server started successfully");
        Ok(())
    }
}

#[derive(Serialize)]
struct RpcVersionInfo {
    #[serde(rename = "solana-core")]
    solana_core: String,
    #[serde(rename = "feature-set")]
    feature_set: u32,
}

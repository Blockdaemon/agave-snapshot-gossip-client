use std::net::SocketAddr;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

use jsonrpc_core::futures::{future, future::ready};
use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{
    hyper::{header, Body, Method, Request, Response, StatusCode},
    RequestMiddlewareAction, ServerBuilder,
};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use regex::Regex;
use url::Url;

use crate::http_proxy;

pub struct RpcServer {
    version: Arc<String>,
    genesis_hash: Arc<String>,
    slot: Arc<AtomicI64>,
    num_peers: Arc<AtomicI64>,
    storage_path: Arc<String>,
    enable_proxy: bool,
}

impl RpcServer {
    pub fn new(
        version: String,
        genesis_hash: String,
        slot: Arc<AtomicI64>,
        num_peers: Arc<AtomicI64>,
        storage_path: String,
        enable_proxy: bool,
    ) -> Self {
        Self {
            version: Arc::new(version),
            genesis_hash: Arc::new(genesis_hash),
            slot: slot,
            num_peers: num_peers,
            storage_path: Arc::new(storage_path),
            enable_proxy,
        }
    }

    pub fn start(&self, addr: SocketAddr) -> jsonrpc_http_server::Server {
        let mut io = IoHandler::new();
        let version = self.version.clone();
        let genesis_hash = self.genesis_hash.clone();
        let slot = self.slot.clone();
        let num_peers = self.num_peers.clone();
        let storage_path = self.storage_path.clone();
        let enable_proxy = self.enable_proxy;

        info!(
            "Starting RPC server on {} with version {} (proxy: {})",
            addr, version, enable_proxy
        );

        // GetVersion
        io.add_method("getVersion", move |_params| {
            ready(Ok(jsonrpc_core::Value::String((*version).clone())))
        });

        // GetGenesisHash
        io.add_method("getGenesisHash", move |_params| {
            ready(Ok(jsonrpc_core::Value::String((*genesis_hash).clone())))
        });

        // GetSlot
        io.add_method("getSlot", move |_params| {
            ready(Ok(jsonrpc_core::Value::Number(
                slot.load(std::sync::atomic::Ordering::SeqCst).into(),
            )))
        });

        // GetNumPeers - unique to us, this is not a standard Solana rpc method
        io.add_method("getNumPeers", move |_params| {
            ready(Ok(jsonrpc_core::Value::Number(
                num_peers.load(std::sync::atomic::Ordering::SeqCst).into(),
            )))
        });

        let server = ServerBuilder::new(io);

        let server = if !storage_path.is_empty() {
            server.request_middleware(move |request: Request<Body>| -> RequestMiddlewareAction {
                if request.method() == &Method::GET {
                    let path = request.uri().path();
                    // Check if the path matches the snapshot pattern
                    if SNAPSHOT_PATH.is_match(path) {
                        // Normalize the storage path and path
                        let target_url_str = match normalize_url(&storage_path, path) {
                            Ok(url) => url,
                            Err(e) => {
                                error!("Failed to normalize URL: {}", e);
                                return http_proxy::respond_with_status(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                );
                            }
                        };

                        if enable_proxy {
                            warn!("Proxying request for {} to {}", path, target_url_str);
                            let client = http_proxy::create_proxy_client();
                            return http_proxy::handle_proxy_request(
                                client,
                                request,
                                target_url_str,
                            );
                        } else {
                            // Existing Redirect Logic
                            warn!("Redirecting request for {} to {}", path, target_url_str);
                            let response = Response::builder()
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .header(header::LOCATION, target_url_str)
                                .body(Body::empty())
                                .unwrap();
                            return RequestMiddlewareAction::Respond {
                                response: Box::pin(future::ok(response)),
                                should_validate_hosts: true,
                            };
                        }
                    } else {
                        // GET request, but path doesn't match snapshot pattern -> 404
                        warn!(
                            "Returning 404 for non-snapshot GET request: {}",
                            request.uri().path()
                        );
                        return http_proxy::respond_with_status(StatusCode::NOT_FOUND);
                    }
                }
                // For non-GET requests (e.g., POST for JSON-RPC), proceed
                debug!(
                    "Proceeding with non-GET request: {} {}",
                    request.method(),
                    request.uri().path()
                );
                RequestMiddlewareAction::Proceed {
                    request,
                    should_continue_on_invalid_cors: true,
                }
            })
        } else {
            server
        };

        server.start_http(&addr).unwrap_or_else(|e| {
            error!("Failed to start RPC server: {}", e);
            std::process::exit(1);
        })
    }
}

lazy_static! {
    static ref SNAPSHOT_PATH: Regex =
        Regex::new(r"^/(genesis|snapshot|incremental-snapshot).*\.tar\.(bz2|zst|gz)$")
            .unwrap_or_else(|e| {
                error!("Failed to compile snapshot path regex: {}", e);
                std::process::exit(1);
            });
}

fn normalize_url(base: &str, path: &str) -> Result<String, String> {
    if base.is_empty() {
        return Err("Base URL is empty".to_string());
    }

    let base_url = Url::parse(base).map_err(|e| format!("Invalid base URL: {}", e))?;

    base_url
        .join(path)
        .map(|url| url.to_string())
        .map_err(|e| format!("Failed to construct URL: {}", e))
}

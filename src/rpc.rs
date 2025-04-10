use std::net::SocketAddr;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

use jsonrpc_core::futures::future::ready;
use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{
    hyper::{header, Body, Method, Request, Response, StatusCode},
    RequestMiddlewareAction, ServerBuilder,
};
use log::{error, info, warn};

use crate::constants::SNAPSHOT_REGEX;
use crate::http_proxy;
use crate::scraper::MetadataScraper;

pub struct RpcServer {
    scraper: Arc<MetadataScraper>,
    version: String,
    num_peers: Arc<AtomicI64>,
    enable_proxy: bool,
}

impl RpcServer {
    pub fn new(
        scraper: Arc<MetadataScraper>,
        version: String,
        num_peers: Arc<AtomicI64>,
        enable_proxy: bool,
    ) -> Self {
        Self {
            scraper,
            version,
            num_peers,
            enable_proxy,
        }
    }

    async fn handle_request_middleware(
        request: Request<Body>,
        scraper: Arc<MetadataScraper>,
        enable_proxy: bool,
    ) -> Result<Response<Body>, hyper::Error> {
        // Handle non-GET requests by letting them proceed to JSON-RPC handler
        if request.method() != &Method::GET {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap());
        }

        let request_path = request.uri().path();

        // Handle non-snapshot GET requests with 404
        if !SNAPSHOT_REGEX.is_match(request_path) {
            warn!(
                "Returning 404 for non-snapshot GET request: {}",
                request_path
            );
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap());
        }

        // Handle snapshot GET requests
        match scraper.build_uri(request.uri()).await {
            Ok(target_uri) => {
                if enable_proxy {
                    let client = http_proxy::create_proxy_client();
                    http_proxy::handle_proxy_request(client, request, target_uri).await
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(header::LOCATION, target_uri.to_string())
                        .body(Body::empty())
                        .unwrap())
                }
            }
            Err(e) => {
                error!("Failed to build URI: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap())
            }
        }
    }

    pub fn start(&self, addr: SocketAddr) -> jsonrpc_http_server::Server {
        let mut io = IoHandler::new();
        let version = self.version.clone();
        let num_peers = self.num_peers.clone();
        let enable_proxy = self.enable_proxy;
        info!(
            "Starting RPC server on {} with version {} (proxy: {})",
            addr, version, enable_proxy
        );

        // GetVersion
        io.add_method("getVersion", move |_params| {
            ready(Ok(jsonrpc_core::Value::String(version.clone())))
        });

        // GetGenesisHash by scraping storage_path
        let genesis_scraper = self.scraper.clone();
        io.add_method("getGenesisHash", move |_params| {
            let scraper = genesis_scraper.clone();
            async move {
                let snapshot_info = scraper.get_cached_snapshot_info().await;
                Ok(jsonrpc_core::Value::String(snapshot_info.genesis_hash))
            }
        });

        // GetSlot by scraping storage_path
        let slot_scraper = self.scraper.clone();
        io.add_method("getSlot", move |_params| {
            let scraper = slot_scraper.clone();
            async move {
                let snapshot_info = scraper.get_cached_snapshot_info().await;
                Ok(jsonrpc_core::Value::Number(snapshot_info.slot.into()))
            }
        });

        // GetNumPeers - unique to us, this is not a standard Solana rpc method
        // The gossip monitor keeps this updated.
        io.add_method("getNumPeers", move |_params| {
            ready(Ok(jsonrpc_core::Value::Number(
                num_peers.load(std::sync::atomic::Ordering::SeqCst).into(),
            )))
        });

        let storage_path_scraper = self.scraper.clone();
        let server = ServerBuilder::new(io);
        let server = if storage_path_scraper.storage_path().is_some() {
            let enable_proxy = enable_proxy;
            server.request_middleware(move |request: Request<Body>| -> RequestMiddlewareAction {
                // Only handle GET requests
                if request.method() == &Method::GET {
                    let request_path = request.uri().path();

                    // Handle snapshot-related GET requests
                    if SNAPSHOT_REGEX.is_match(request_path) {
                        let scraper = storage_path_scraper.clone();
                        let enable_proxy = enable_proxy;
                        let future =
                            Self::handle_request_middleware(request, scraper, enable_proxy);
                        return RequestMiddlewareAction::Respond {
                            response: Box::pin(future),
                            should_validate_hosts: true,
                        };
                    }

                    // Handle non-snapshot GET requests with 404
                    warn!(
                        "Returning 404 for non-snapshot GET request: {}",
                        request_path
                    );
                    return RequestMiddlewareAction::Respond {
                        response: Box::pin(async {
                            Ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::empty())
                                .unwrap())
                        }),
                        should_validate_hosts: true,
                    };
                }

                // Let non-GET requests pass through to JSON-RPC handler
                RequestMiddlewareAction::Proceed {
                    request,
                    should_continue_on_invalid_cors: false,
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

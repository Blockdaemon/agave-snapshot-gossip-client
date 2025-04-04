use jsonrpc_core::futures::{future, future::ready};
use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{
    hyper::{Body, Method, Request, Response, StatusCode},
    RequestMiddlewareAction, ServerBuilder,
};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::SocketAddr;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub struct RpcServer {
    version: Arc<String>,
    genesis_hash: Arc<String>,
    slot: Arc<AtomicI64>,
    num_peers: Arc<AtomicI64>,
    storage_server: Arc<String>,
}

impl RpcServer {
    pub fn new(
        version: String,
        genesis_hash: String,
        slot: Arc<AtomicI64>,
        num_peers: Arc<AtomicI64>,
        storage_server: String,
    ) -> Self {
        Self {
            version: Arc::new(version),
            genesis_hash: Arc::new(genesis_hash),
            slot: slot,
            num_peers: num_peers,
            storage_server: Arc::new(storage_server),
        }
    }

    pub fn start(&self, addr: SocketAddr) -> jsonrpc_http_server::Server {
        let mut io = IoHandler::new();
        let version = self.version.clone();
        let genesis_hash = self.genesis_hash.clone();
        let slot = self.slot.clone();
        let num_peers = self.num_peers.clone();
        let storage_server = self.storage_server.clone();

        println!("Starting RPC server on {} with version {}", addr, version);

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

        ServerBuilder::new(io)
            .request_middleware(move |request: Request<Body>| -> RequestMiddlewareAction {
                if request.method() == &Method::GET {
                    let path = request.uri().path();
                    if ARCHIVE_PATH.is_match(path) {
                        let new_location = format!("{}{}", storage_server, path);
                        let response = Response::builder()
                            .status(StatusCode::TEMPORARY_REDIRECT)
                            .header("Location", new_location)
                            .body(Body::empty())
                            .unwrap();
                        return RequestMiddlewareAction::Respond {
                            response: Box::pin(future::ok(response)),
                            should_validate_hosts: true,
                        };
                    }
                    // Return 404 for GET requests that don't match the archive pattern
                    let response = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .unwrap();
                    return RequestMiddlewareAction::Respond {
                        response: Box::pin(future::ok(response)),
                        should_validate_hosts: true,
                    };
                }
                RequestMiddlewareAction::Proceed {
                    request,
                    should_continue_on_invalid_cors: true,
                }
            })
            .start_http(&addr)
            .expect("Failed to start RPC server")
    }
}

lazy_static! {
    static ref ARCHIVE_PATH: Regex =
        Regex::new(r"^/(genesis|snapshot|incremental-snapshot).*\.tar\.(bz2|zst|gz)$").unwrap();
}

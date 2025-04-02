use jsonrpc_core::futures::future::ready;
use jsonrpc_core::IoHandler;
use jsonrpc_http_server::ServerBuilder;
use std::net::SocketAddr;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

pub struct RpcServer {
    version: Arc<String>,
    genesis_hash: Arc<String>,
    slot: Arc<AtomicI64>,
    num_peers: Arc<AtomicI64>,
}

impl RpcServer {
    pub fn new(
        version: String,
        genesis_hash: String,
        slot: Arc<AtomicI64>,
        num_peers: Arc<AtomicI64>,
    ) -> Self {
        Self {
            version: Arc::new(version),
            genesis_hash: Arc::new(genesis_hash),
            slot: slot,
            num_peers: num_peers,
        }
    }

    pub fn start(&self, addr: SocketAddr) -> jsonrpc_http_server::Server {
        let mut io = IoHandler::new();
        let version = self.version.clone();
        let genesis_hash = self.genesis_hash.clone();
        let slot = self.slot.clone();
        let num_peers = self.num_peers.clone();

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

        // GetNumPeers
        io.add_method("getNumPeers", move |_params| {
            ready(Ok(jsonrpc_core::Value::Number(
                num_peers.load(std::sync::atomic::Ordering::SeqCst).into(),
            )))
        });

        ServerBuilder::new(io)
            .start_http(&addr)
            .expect("Failed to start RPC server")
    }
}

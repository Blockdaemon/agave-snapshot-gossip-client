mod config;
mod constants;
mod gossip;
mod rpc;
mod stun;
mod upnp;

use easy_upnp::PortMappingProtocol;
use env_logger;
use gossip::make_gossip_node;
use log::{error, info, warn};
use rpc::RpcServer;
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_streamer::socket::SocketAddrSpace;
use solana_version::Version;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;
use std::thread;

pub use constants::*; // Re-export the constants

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let config = config::load_config();
    let node_keypair = read_keypair_file(&config.keypair_path).unwrap_or_else(|err| {
        warn!(
            "{} not found, generating new keypair: {}",
            config.keypair_path, err
        );
        Keypair::new()
    });
    info!("Our pubkey: {}", node_keypair.pubkey());

    let resolved = config.resolve().await.map_err(|e| {
        error!("Failed to resolve configuration: {:?}", e);
        e
    })?;
    info!("Public address: {}", resolved.public_addr);

    if resolved.entrypoints.is_empty() {
        return Err("No entrypoints configured".into());
    }

    // Try to set up UPnP port forwarding BEFORE signal handler
    if resolved.enable_upnp {
        upnp::setup_port_forwarding(vec![
            (DEFAULT_GOSSIP_PORT, PortMappingProtocol::UDP),
            (resolved.rpc_listen.port(), PortMappingProtocol::TCP),
        ]);
    }

    info!("Setting up signal handler");
    let exit = Arc::new(AtomicBool::new(false));
    let e = exit.clone();
    let signal_handler = tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| {
                error!("Failed to install SIGTERM handler: {}", e);
                std::process::exit(1);
            });
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .unwrap_or_else(|e| {
                error!("Failed to install SIGINT handler: {}", e);
                std::process::exit(1);
            });
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                warn!("Received CTRL+C");
            }
            _ = sigterm.recv() => {
                warn!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                warn!("Received SIGINT");
            }
        }
        e.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    info!("Starting gossip service...");
    // Start gossip service
    let gossip_addr = &SocketAddr::new(resolved.public_addr, DEFAULT_GOSSIP_PORT);
    let rpc_addr = &SocketAddr::new(resolved.public_addr, resolved.rpc_listen.port());
    let (gossip_service, _, cluster_info) = make_gossip_node(
        node_keypair,
        resolved.entrypoints,
        exit.clone(),
        Some(gossip_addr),
        Some(rpc_addr),
        0,
        true,
        SocketAddrSpace::Unspecified,
    );
    info!("Started gossip service");

    info!("Starting monitor service...");
    let num_peers = Arc::new(AtomicI64::new(0));
    let monitor_handle = tokio::spawn({
        let cluster_info = cluster_info.clone();
        let exit = exit.clone();
        let num_peers = num_peers.clone();
        async move {
            gossip::monitor_gossip_service(cluster_info, exit, num_peers).await;
        }
    });
    info!("Started monitor service");

    info!("Starting RPC server on {}...", resolved.rpc_listen);
    let slot = Arc::new(AtomicI64::new(0));
    let rpc_server = RpcServer::new(
        Version::default().to_string(),
        resolved.genesis_hash,
        slot.clone(),
        num_peers.clone(),
        resolved.storage_server,
    );
    let _rpc_server = rpc_server.start(resolved.rpc_listen);
    info!("Started RPC server");

    warn!("Ready to accept connections");

    // Wait for signal or ctrl+c
    signal_handler.await.unwrap_or_else(|e| {
        error!("Failed to join signal handler: {}", e);
        std::process::exit(1);
    });

    // Clean up port forwarding if enabled
    if resolved.enable_upnp {
        upnp::cleanup_port_forwarding();
    }

    // Stop RPC server
    info!("Stopping RPC server...");
    thread::spawn(move || {
        _rpc_server.close();
    });

    info!("Signaling gossip service and monitor to exit...");
    // Signal exit to gossip service and monitor
    exit.store(true, std::sync::atomic::Ordering::SeqCst);
    // Join gossip service
    gossip_service.join().unwrap();
    info!("Gossip service shutdown complete");

    // Wait for monitor to complete
    monitor_handle.await.unwrap_or_else(|e| {
        error!("Failed to join monitor task: {}", e);
        std::process::exit(1);
    });
    info!("Gossip monitor shutdown complete");

    warn!("Shutting down...");
    std::process::exit(0);
}

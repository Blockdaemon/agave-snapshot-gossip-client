mod config;
mod constants;
mod gossip;
mod http_proxy;
mod rpc;
mod scraper;
mod stun;
mod upnp;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16};
use std::sync::Arc;

use clap::Parser;
use env_logger;
use igd::PortMappingProtocol;
use log::{error, info, warn};
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_version::Version;

use gossip::{make_gossip_node, GossipMonitor};
use rpc::RpcServer;
use scraper::MetadataScraper;

#[derive(Parser)]
#[command(author, about, long_about = None, disable_version_flag = true)]
struct Cli {
    /// Print version information and exit
    #[arg(short, long)]
    version: bool,

    /// Path to config file
    #[arg(short, long, default_value = crate::constants::DEFAULT_CONFIG_PATH)]
    config: String,
}

async fn setup_signal_handler(exit: Arc<AtomicBool>) -> Result<(), tokio::task::JoinError> {
    tokio::spawn(async move {
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
        exit.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.version {
        println!("agave-snapshot-gossip-client {}", env!("CARGO_PKG_VERSION"));
        println!("Build timestamp: {}", env!("BUILD_TIMESTAMP"));
        println!("Git tag: {}", env!("GIT_TAG"));
        println!("Git SHA: {}", env!("GIT_SHA"));
        return Ok(());
    }

    env_logger::init();
    let config = config::load_config(Some(&cli.config));
    let resolved = config.resolve().await.map_err(|e| {
        error!("Failed to resolve configuration: {:?}", e);
        e
    })?;

    let node_keypair = read_keypair_file(&resolved.keypair_path).unwrap_or_else(|err| {
        warn!(
            "{} not found, generating new keypair: {}",
            resolved.keypair_path, err
        );
        Keypair::new()
    });
    info!("Our pubkey: {}", node_keypair.pubkey());

    info!("Public address: {}", resolved.public_ip);

    if resolved.entrypoints.is_empty() {
        return Err("No entrypoints configured".into());
    }

    // Try to set up UPnP port forwarding BEFORE signal handler
    if resolved.enable_upnp {
        if let Err(e) = upnp::setup_port_forwarding(
            vec![
                (resolved.gossip_port, PortMappingProtocol::UDP),
                (resolved.rpc_port, PortMappingProtocol::TCP),
            ],
            None,
        ) {
            error!("Failed to set up UPnP port forwarding: {}", e);
        }
    }

    // We make 3 exit clones, one for the signal handler, one for the gossip service, and one for the monitor
    let exit = Arc::new(AtomicBool::new(false));

    info!("Setting up signal handler");
    let signal_handler = setup_signal_handler(exit.clone()); // clone #1

    // Start gossip service
    let listen_addr = &SocketAddr::new(resolved.listen_ip, resolved.gossip_port);
    let rpc_addr = &SocketAddr::new(resolved.public_ip, resolved.rpc_port);
    let rpc_pubsub_addr = &SocketAddr::new(resolved.public_ip, resolved.rpc_port + 1);
    info!("Starting gossip service, reporting rpc {:?}", rpc_addr);
    let (gossip_service, cluster_info) = make_gossip_node(
        node_keypair,
        resolved.entrypoints,
        exit.clone(),          // clone #2
        listen_addr,           // listen_ip:gossip_port
        resolved.public_ip,    // Issue #18: how does the stock agave validator do this?
        Some(rpc_addr),        // public_ip:rpc_port
        Some(rpc_pubsub_addr), // public_ip:rpc_port+1
        resolved.expected_shred_version,
    );
    info!("Started gossip service");

    info!("Starting monitor service...");
    let num_peers = Arc::new(AtomicI64::new(0));
    let shred_version = Arc::new(AtomicU16::new(0));
    let monitor_handle = tokio::spawn({
        let cluster_info = cluster_info.clone();
        let exit = exit.clone(); // clone #3
        let num_peers = num_peers.clone(); // modifed by gossip monitor
        let shred_version = shred_version.clone(); // modifed by gossip monitor
        async move {
            cluster_info
                .monitor_gossip(exit, num_peers, shred_version)
                .await;
        }
    });
    info!("Started monitor service");

    let scraper = MetadataScraper::new(resolved.storage_path, resolved.expected_genesis_hash);
    let rpc_server = RpcServer::new(
        Arc::new(scraper),
        Version::default().to_string(),
        num_peers.clone(),
        shred_version.clone(),
        resolved.enable_proxy,
    );
    let rpc_listen = SocketAddr::new(resolved.listen_ip, resolved.rpc_port);
    info!("Starting RPC server on {}...", rpc_listen);
    let _rpc_server = rpc_server.start(rpc_listen);
    info!("Started RPC server");

    warn!("Ready to accept connections");

    // Wait for signal or ctrl+c
    signal_handler.await.unwrap_or_else(|e| {
        error!("Failed to join signal handler: {}", e);
        std::process::exit(1);
    });

    // Clean up port forwarding if enabled
    if resolved.enable_upnp {
        if let Err(e) = upnp::cleanup_port_forwarding() {
            error!("Failed to cleanup UPnP port forwarding: {}", e);
        }
    }

    // Stop RPC server
    info!("Stopping RPC server...");
    // drop runtime outside the async context
    std::thread::spawn(move || {
        _rpc_server.close();
    });

    info!("Signaling gossip service and monitor to exit...");
    // Signal exit to gossip service and monitor
    exit.store(true, std::sync::atomic::Ordering::SeqCst);

    // Wait for monitor to complete
    monitor_handle.await.unwrap_or_else(|e| {
        error!("Failed to join monitor task: {}", e);
        std::process::exit(1);
    });
    info!("Gossip monitor shutdown complete");

    // Join gossip service
    info!("Waiting for gossip service shutdown...");
    gossip_service.join().unwrap();
    info!("Gossip service shutdown complete");

    warn!("Shutting down...");
    std::process::exit(0);
}

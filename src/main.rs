mod config;
mod constants;
mod rpc;
mod stun;
mod upnp;

use env_logger;
use log::{debug, error, info, warn};
use rand;
use rpc::RpcServer;
use solana_gossip::cluster_info::ClusterInfo;
use solana_gossip::gossip_service::make_gossip_node;
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_streamer::socket::SocketAddrSpace;
use solana_version::Version;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use surge_ping::{Client as PingClient, Config as PingConfig, PingIdentifier};

pub use constants::*; // Re-export the constants

async fn monitor_gossip_service(
    cluster_info: Arc<ClusterInfo>,
    exit: Arc<AtomicBool>,
    num_peers: Arc<AtomicI64>,
) {
    warn!("Connecting to gossip...");
    let start = std::time::Instant::now();
    let mut max_peer_count = 1;
    let mut last_peer_count = 0;
    let mut connected = false;
    while !exit.load(std::sync::atomic::Ordering::SeqCst) {
        let peer_count = cluster_info.all_peers().len();
        if peer_count > 1 && !connected {
            connected = true;
            warn!("Connected to gossip, {} peers", peer_count);
        }

        if peer_count != last_peer_count {
            num_peers.store(
                peer_count.try_into().unwrap(),
                std::sync::atomic::Ordering::SeqCst,
            );
            last_peer_count = peer_count;
        }

        if peer_count > max_peer_count {
            warn!(
                "Current peer count: {} (elapsed: {}s)",
                peer_count,
                start.elapsed().as_secs()
            );
            for (peer, _) in cluster_info.all_peers() {
                debug!(
                    "    - Peer: {:?} {:?} {:?}",
                    peer.pubkey(),
                    peer.shred_version(),
                    peer.gossip().map_or_else(
                        || { String::from("<no addr>") },
                        |addr| addr.ip().to_string()
                    ),
                )
            }
            max_peer_count = peer_count;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    warn!("Monitoring gossip service exited");
}

async fn test_entrypoint_latency(addr: &SocketAddr) -> Option<Duration> {
    let client = match PingClient::new(&PingConfig::default()) {
        Ok(c) => c,
        Err(_) => return None,
    };

    let mut pinger = client
        .pinger(addr.ip(), PingIdentifier(rand::random()))
        .await;
    pinger.timeout(Duration::from_secs(1));

    // Send 3 pings and take average
    let mut total_rtt = Duration::ZERO;
    let mut successful = 0;

    for i in 0..3 {
        if let Ok((_packet, rtt)) = pinger.ping(surge_ping::PingSequence(i), &[0; 0]).await {
            total_rtt += rtt;
            successful += 1;
        }
    }

    if successful > 0 {
        Some(total_rtt / successful)
    } else {
        None
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let config = config::load_config();
    let node_keypair = read_keypair_file(&config.keypair_path).unwrap_or_else(|_err| {
        warn!("{} not found, generating new keypair", config.keypair_path);
        Keypair::new()
    });
    info!("Our pubkey: {}", node_keypair.pubkey());

    let resolved = config.resolve().await;
    info!("Public address: {}", resolved.public_addr);

    if resolved.entrypoints.is_empty() {
        error!("No entrypoints configured!");
        return;
    }

    info!("Selecting the best entrypoint");
    let best_entrypoint = if !resolved.entrypoints.is_empty() {
        let mut best = &resolved.entrypoints[0];
        let mut best_latency = Duration::MAX;

        for entrypoint in &resolved.entrypoints {
            if let Some(latency) = test_entrypoint_latency(entrypoint).await {
                if latency < best_latency {
                    best_latency = latency;
                    best = entrypoint;
                }
            }
        }
        info!("Best entrypoint: {} (latency: {:?})", best, best_latency);
        Some(best)
    } else {
        None
    };

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

    // Try to set up UPnP port forwarding if enabled
    if resolved.enable_upnp {
        upnp::setup_port_forwarding(vec![DEFAULT_GOSSIP_PORT, resolved.rpc_listen.port()]);
    }

    info!("Starting gossip service...");
    // Start gossip service
    let gossip_addr = &SocketAddr::new(resolved.public_addr, DEFAULT_GOSSIP_PORT);
    let (gossip_service, _, cluster_info) = make_gossip_node(
        node_keypair,
        best_entrypoint,
        exit.clone(),
        Some(gossip_addr),
        0,
        true,
        SocketAddrSpace::Unspecified,
    );
    info!("Started gossip service");

    let slot = Arc::new(AtomicI64::new(0));
    let num_peers = Arc::new(AtomicI64::new(0));
    let rpc_server = RpcServer::new(
        Version::default().to_string(),
        resolved.genesis_hash,
        slot.clone(),
        num_peers.clone(),
        resolved.storage_server,
    );
    let _rpc_server = rpc_server.start(resolved.rpc_listen);
    info!("Started RPC server on {}", resolved.rpc_listen);

    // Create a task for monitoring
    let monitor_handle = tokio::spawn({
        let cluster_info = cluster_info.clone();
        let exit = exit.clone();
        let num_peers = num_peers.clone();
        async move {
            monitor_gossip_service(cluster_info, exit, num_peers).await;
        }
    });

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

    info!("Signaling gossip service and monitor to exit");
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

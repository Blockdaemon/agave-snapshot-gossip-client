mod config;
mod constants;
mod rpc;
mod stun;
mod upnp;

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
    println!("Monitoring gossip service");
    let start = std::time::Instant::now();
    let mut last_peer_count = 0;
    while !exit.load(std::sync::atomic::Ordering::SeqCst) {
        let peer_count = cluster_info.all_peers().len();
        if peer_count != last_peer_count {
            num_peers.store(
                peer_count.try_into().unwrap(),
                std::sync::atomic::Ordering::SeqCst,
            );
            println!(
                "Current peer count: {} (elapsed: {}s)",
                peer_count,
                start.elapsed().as_secs()
            );
            for (peer, _) in cluster_info.all_peers() {
                println!(
                    "    - Peer: {:?} {:?} {:?}",
                    peer.pubkey(),
                    peer.shred_version(),
                    peer.gossip().expect("No gossip addr").ip(),
                )
            }
            last_peer_count = peer_count;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!("Monitoring gossip service complete");
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
    let config = config::load_config();
    let node_keypair = read_keypair_file(&config.keypair_path).unwrap_or_else(|_err| {
        println!("{} not found, generating new keypair", config.keypair_path);
        Keypair::new()
    });
    println!("Our pubkey: {}", node_keypair.pubkey());

    let resolved = config.resolve();
    println!("Public address: {}", resolved.public_addr);

    if resolved.entrypoints.is_empty() {
        println!("No entrypoints configured!");
        return;
    }

    let exit = Arc::new(AtomicBool::new(false));
    let e = exit.clone();

    println!("Selecting the best entrypoint");
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
        println!("Best entrypoint: {} (latency: {:?})", best, best_latency);
        Some(best)
    } else {
        None
    };

    // Try to set up UPnP port forwarding if enabled
    if resolved.enable_upnp {
        upnp::setup_port_forwarding(vec![DEFAULT_GOSSIP_PORT, resolved.rpc_listen.port()]);
    }

    println!("Setting up signal handler");
    let signal_handler = tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Received CTRL+C");
            }
            _ = sigterm.recv() => {
                println!("Received SIGTERM");
            }
        }
        e.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    println!("Starting gossip service...");
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
    println!("Started gossip service");

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
    println!("Started RPC server on {}", resolved.rpc_listen);

    // Create a task for monitoring
    let monitor_handle = tokio::spawn({
        let cluster_info = cluster_info.clone();
        let exit = exit.clone();
        let num_peers = num_peers.clone();
        async move {
            monitor_gossip_service(cluster_info, exit, num_peers).await;
        }
    });

    // Replace the ctrl_c().await with waiting for the signal handler
    signal_handler.await.expect("Failed to join signal handler");

    // Stop RPC server
    println!("Stopping RPC server...");
    thread::spawn(move || {
        _rpc_server.close();
    });

    println!("Signaling gossip service and monitor to exit");
    // Signal exit to gossip service and monitor
    exit.store(true, std::sync::atomic::Ordering::SeqCst);
    // Join gossip service
    gossip_service.join().unwrap();
    println!("Gossip service shutdown complete");
    // Wait for monitor to complete
    monitor_handle.await.expect("Failed to join monitor task");
    println!("Gossip monitor shutdown complete");

    // Clean up port forwarding if enabled
    if resolved.enable_upnp {
        upnp::cleanup_port_forwarding();
    }
}

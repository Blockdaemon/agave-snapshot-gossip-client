mod config;
mod constants;
mod rpc;
mod stun;
mod upnp;

use rpc::RpcServer;
use signal_hook::{consts::signal::*, iterator::Signals};
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

pub use constants::*; // Re-export the constants

fn monitor_gossip_service(
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
        thread::sleep(Duration::from_secs(1));
    }
    println!("Monitoring gossip service complete");
}

fn main() {
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

    // Try to set up UPnP port forwarding if enabled
    if resolved.enable_upnp {
        upnp::setup_port_forwarding(vec![DEFAULT_GOSSIP_PORT, resolved.rpc_listen.port()]);
    }

    let exit = Arc::new(AtomicBool::new(false));
    let e = exit.clone();

    // Handle both SIGINT and SIGTERM
    let mut signals = Signals::new(&[SIGINT, SIGTERM]).expect("Error setting up signal handlers");
    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {}", sig);
            e.store(true, std::sync::atomic::Ordering::SeqCst);
            break;
        }
    });

    println!("Starting gossip service");
    // Start gossip service
    let (gossip_service, _, cluster_info) = make_gossip_node(
        node_keypair,
        Some(&resolved.entrypoints[0]),
        exit.clone(),
        Some(&SocketAddr::new(resolved.public_addr, DEFAULT_GOSSIP_PORT)),
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
    );
    let _rpc_server = rpc_server.start(resolved.rpc_listen);
    println!("Started RPC server on {}", resolved.rpc_listen);

    monitor_gossip_service(cluster_info, exit.clone(), num_peers.clone());

    println!("Shutting down gossip service...");
    // Now we set it to true to trigger shutdown
    exit.store(true, std::sync::atomic::Ordering::SeqCst);
    gossip_service.join().unwrap();
    println!("Gossip service shutdown complete");

    // Clean up port forwarding if enabled
    if resolved.enable_upnp {
        upnp::cleanup_port_forwarding();
    }
}

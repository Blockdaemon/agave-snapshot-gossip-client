use log::{debug, info, warn};
use solana_gossip::{
    cluster_info::ClusterInfo, contact_info::ContactInfo, gossip_service::GossipService,
};
use solana_sdk::signature::{Keypair, Signer};
use solana_streamer::socket::SocketAddrSpace;
use std::sync::atomic::AtomicI64;
use std::time::Duration;
use std::{
    net::{SocketAddr, TcpListener},
    sync::{atomic::AtomicBool, Arc},
};
use tokio;

/// Makes a spy or gossip node based on whether or not a gossip_addr was passed in
/// Pass in a gossip addr to fully participate in gossip instead of relying on just pulls
/// Accepts multiple entrypoints for redundancy
/// This is a modified version of
/// solana_gossip::gossip_service::make_gossip_node that takes an entrypoints
/// vector instead of a single entrypoint, and an optional rpc_addr to set on the node
pub fn make_gossip_node(
    keypair: Keypair,
    entrypoints: Vec<SocketAddr>,
    exit: Arc<AtomicBool>,
    gossip_addr: Option<&SocketAddr>,
    rpc_addr: Option<&SocketAddr>,
    rpc_pubsub_addr: Option<&SocketAddr>,
    shred_version: u16,
    should_check_duplicate_instance: bool,
    socket_addr_space: SocketAddrSpace,
) -> (GossipService, Option<TcpListener>, Arc<ClusterInfo>) {
    let (node, gossip_socket, ip_echo) = if let Some(gossip_addr) = gossip_addr {
        ClusterInfo::gossip_node(keypair.pubkey(), gossip_addr, shred_version)
    } else {
        ClusterInfo::spy_node(keypair.pubkey(), shred_version)
    };

    let cluster_info = ClusterInfo::new(node, Arc::new(keypair), socket_addr_space);

    // Add all entrypoints to the cluster info
    cluster_info.set_entrypoints(
        entrypoints
            .iter()
            .map(|addr| ContactInfo::new_gossip_entry_point(addr))
            .collect(),
    );

    // Set RPC/PubSub address on the node
    if let Some(addr) = rpc_addr {
        cluster_info.my_contact_info().set_rpc(*addr).unwrap();
    }
    if let Some(addr) = rpc_pubsub_addr {
        cluster_info
            .my_contact_info()
            .set_rpc_pubsub(*addr)
            .unwrap();
    }

    let cluster_info = Arc::new(cluster_info);
    let gossip_service = GossipService::new(
        &cluster_info,
        None,
        gossip_socket,
        None,
        should_check_duplicate_instance,
        None,
        exit,
    );

    (gossip_service, ip_echo, cluster_info)
}

pub async fn monitor_gossip_service(
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
            debug!("\n{}\n", cluster_info.rpc_info_trace());
            num_peers.store(
                peer_count.try_into().unwrap(),
                std::sync::atomic::Ordering::SeqCst,
            );
            last_peer_count = peer_count;
        }

        if peer_count > max_peer_count {
            info!(
                "Current peer count: {} (elapsed: {}s)",
                peer_count,
                start.elapsed().as_secs()
            );
            for (peer, _) in cluster_info.all_peers() {
                if peer.shred_version() != 0 && peer.rpc().is_some() {
                    debug!(
                        "    - Peer: {:?} {:?} {:?} {:?}",
                        peer.pubkey(),
                        peer.shred_version(),
                        peer.gossip().map_or_else(
                            || { String::from("<no addr>") },
                            |addr| addr.ip().to_string()
                        ),
                        peer.rpc()
                            .map_or_else(|| { String::from("<no rpc>") }, |addr| addr.to_string()),
                    )
                }
            }
            max_peer_count = peer_count;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    info!("Gossip monitor service exited");
}

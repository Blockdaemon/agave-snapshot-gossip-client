use std::future::Future;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, info, warn};
use solana_gossip::cluster_info::ClusterInfo;
use solana_gossip::contact_info::ContactInfo;
use solana_gossip::gossip_service::GossipService;
use solana_sdk::signature::{Keypair, Signer};
use solana_streamer::socket::SocketAddrSpace;
use tokio;

trait ContactInfoDebugExt {
    fn debug(&self) -> String;
}

impl ContactInfoDebugExt for ContactInfo {
    fn debug(&self) -> String {
        format!(
            "{:?} {:?} {:?} {:?}",
            self.pubkey(),
            self.shred_version(),
            self.gossip().map_or_else(
                || { String::from("<no addr>") },
                |addr| addr.ip().to_string()
            ),
            self.rpc()
                .map_or_else(|| { String::from("<no rpc>") }, |addr| addr.to_string()),
        )
    }
}

pub trait GossipMonitor {
    fn monitor_gossip(
        &self,
        exit: Arc<AtomicBool>,
        num_peers: Arc<AtomicI64>,
        shred_version: Arc<AtomicU16>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

impl GossipMonitor for Arc<ClusterInfo> {
    fn monitor_gossip(
        &self,
        exit: Arc<AtomicBool>,
        num_peers: Arc<AtomicI64>,
        shred_version: Arc<AtomicU16>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            warn!("Connecting to gossip...");
            let start = std::time::Instant::now();
            let mut last_peer_count = 0;
            let mut last_shred_version = 0;
            let mut connected = false;
            while !exit.load(std::sync::atomic::Ordering::SeqCst) {
                let peer_count = self.all_peers().len();
                if peer_count > 2 && !connected {
                    connected = true;
                    warn!("Connected to gossip, {} peers", peer_count);
                }

                let peers_changed = peer_count != last_peer_count;

                for (peer, _) in self.all_peers() {
                    let is_me = peer.pubkey() == &self.id();
                    let shred_ver = peer.shred_version();

                    // Update shred version if it's me and has changed
                    if is_me && shred_ver != 0 && shred_ver != last_shred_version {
                        debug!(
                            "changed shred version {} -> {}",
                            last_shred_version, shred_ver
                        );
                        shred_version.store(shred_ver, std::sync::atomic::Ordering::SeqCst);
                        last_shred_version = shred_ver;
                    }

                    // Log peer info if peers changed and it's either me or a valid peer
                    if peers_changed && (is_me || (shred_ver != 0 && peer.rpc().is_some())) {
                        debug!("{}: {}", if is_me { "  me" } else { "Peer" }, peer.debug());
                    }
                }

                if peers_changed {
                    info!(
                        "Current peer count: {} (elapsed: {}s)",
                        peer_count,
                        start.elapsed().as_secs()
                    );
                    num_peers.store(
                        peer_count.try_into().unwrap(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    last_peer_count = peer_count;
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            info!("Gossip monitor service exited");
        })
    }
}

/// Makes a spy or gossip node based on whether or not a gossip_addr was passed in
/// Pass in a gossip addr to fully participate in gossip instead of relying on just pulls
/// Accepts multiple entrypoints for redundancy
/// This is a complete rewrite of solana_gossip::gossip_service::make_gossip_node
/// Different parameters:
/// * Entrypoints vector instead of a single entrypoint
/// * listen_addr/public_ip instead of an optional gossip_addr
/// * rpc_addr/rpc_pubsub_addr to add explicitly to ContactInfo
pub fn make_gossip_node(
    keypair: Keypair,
    entrypoints: Vec<SocketAddr>,
    exit: Arc<AtomicBool>,
    listen_addr: &SocketAddr,
    public_ip: IpAddr,
    rpc_addr: Option<&SocketAddr>,
    rpc_pubsub_addr: Option<&SocketAddr>,
    shred_version: u16,
) -> (GossipService, Arc<ClusterInfo>) {
    let (node, gossip_socket) = {
        // Create a ContactInfo with both gossip and RPC sockets set
        let mut node = ContactInfo::new(
            keypair.pubkey(),
            solana_sdk::timing::timestamp(),
            shred_version,
        );

        // Advertise the public gossip address
        let gossip_addr = SocketAddr::new(public_ip, listen_addr.port());
        node.set_gossip(gossip_addr).unwrap_or_else(|e| {
            panic!("Failed to set gossip address: {:?} {:?}", gossip_addr, e);
        });

        // Advertise the public RPC address if provided
        if let Some(addr) = rpc_addr {
            node.set_rpc(*addr).unwrap();
            if node.rpc().is_none() {
                panic!("RPC address was not set despite successful set_rpc() call!");
            }
        }

        // Advertise the public RPC PubSub address if provided
        if let Some(addr) = rpc_pubsub_addr {
            node.set_rpc_pubsub(*addr).unwrap();
            if node.rpc_pubsub().is_none() {
                panic!("RPC PubSub address was not set despite successful set_rpc_pubsub() call!");
            }
        }

        // Do this instead of ClusterInfo:gossip_node(keypair, gossip_addr, shred_version) so we can do it after set_rpc()
        info!("Binding to gossip socket: {:?}", listen_addr);
        let gossip_socket = UdpSocket::bind(listen_addr).unwrap();

        (node, gossip_socket)
    };

    let cluster_info = ClusterInfo::new(node, Arc::new(keypair), SocketAddrSpace::Unspecified);

    // Add all entrypoints to the cluster info
    cluster_info.set_entrypoints(
        entrypoints
            .iter()
            .map(|addr| ContactInfo::new_gossip_entry_point(addr))
            .collect(),
    );

    // Verify the RPC address was set if it was provided
    if rpc_addr.is_some() && cluster_info.my_contact_info().rpc().is_none() {
        panic!("RPC address was not set despite successful set_rpc() call!");
    }

    let cluster_info = Arc::new(cluster_info);
    let gossip_service =
        GossipService::new(&cluster_info, None, gossip_socket, None, true, None, exit);

    (gossip_service, cluster_info)
}

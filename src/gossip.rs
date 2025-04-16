use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, error, info, warn};
use solana_gossip::gossip_service::GossipService;
use solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo};
use solana_sdk::hash::Hash;
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_streamer::socket::SocketAddrSpace;
use tokio;

// Our local crates
use super::config::ResolvedConfig;
use super::ip_echo;
use super::scraper::{MetadataScraper, SnapshotHashes};

// Constants
use crate::constants::DEFAULT_GOSSIP_CRDS_TTL_SECS;
const MIN_PEERS: usize = 2;

macro_rules! decode_hash {
    ($hash_str:expr) => {
        Hash::from_str($hash_str).map_err(anyhow::Error::msg)
    };
}

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

#[derive(Debug)]
struct GossipMonitorState {
    last_push: Instant,
    last_snapshot_hashes: Option<SnapshotHashes>,
    connected: bool,
    last_peer_count: usize,
    last_shred_version: u16,
}

impl GossipMonitorState {
    fn new() -> Self {
        Self {
            last_push: Instant::now(),
            last_snapshot_hashes: None,
            connected: false,
            last_peer_count: 0,
            last_shred_version: 0,
        }
    }

    fn should_push(&self, current_hashes: &SnapshotHashes) -> (bool, bool) {
        (
            self.last_push.elapsed() > Duration::from_secs(DEFAULT_GOSSIP_CRDS_TTL_SECS - 2),
            self.last_snapshot_hashes.as_ref() != Some(current_hashes),
        )
    }

    fn push_snapshot_hashes(
        &mut self,
        cluster_info: &ClusterInfo,
        snapshot_hashes: SnapshotHashes,
    ) -> Result<()> {
        let (full_slot, full_hash, incremental_hashes) = decode_snapshot_hashes(&snapshot_hashes)?;

        info!("Pushing snapshot hashes: {:?}", snapshot_hashes);
        cluster_info
            .push_snapshot_hashes((full_slot, full_hash), incremental_hashes)
            .map_err(|e| anyhow::anyhow!("Failed to push snapshot hashes: {}", e))?;

        if let Some(hashes) = cluster_info.get_snapshot_hashes_for_node(&cluster_info.id()) {
            debug!("{} {:?}", cluster_info.id(), hashes);
        }
        self.last_push = Instant::now();
        self.last_snapshot_hashes = Some(snapshot_hashes);
        Ok(())
    }
}

trait GossipMonitor {
    fn monitor_gossip(
        &self,
        scraper: Arc<MetadataScraper>,
        exit: Arc<AtomicBool>,
        num_peers: Arc<AtomicI64>,
        shred_version: Arc<AtomicU16>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

fn decode_snapshot_hashes(
    snapshot_hashes: &SnapshotHashes,
) -> Result<(u64, Hash, Vec<(u64, Hash)>)> {
    let (full_slot, full_hash, incremental_hashes) = snapshot_hashes
        .convert_snapshot_hashes()
        .map_err(|e| anyhow::anyhow!("Failed to convert snapshot hashes: {}", e))?;

    let full_hash = decode_hash!(&full_hash)
        .map_err(|e| anyhow::anyhow!("Failed to decode full hash: {}", e))?;

    let incremental_hashes = incremental_hashes
        .into_iter()
        .map(|(slot, hash)| decode_hash!(&hash).map(|hash| (slot, hash)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to decode incremental hashes: {}", e))?;

    Ok((full_slot, full_hash, incremental_hashes))
}

impl GossipMonitor for Arc<ClusterInfo> {
    fn monitor_gossip(
        &self,
        scraper: Arc<MetadataScraper>,
        exit: Arc<AtomicBool>,
        num_peers: Arc<AtomicI64>,
        shred_version: Arc<AtomicU16>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            warn!("Connecting to gossip...");
            let start = Instant::now();
            let mut state = GossipMonitorState::new();

            while !exit.load(std::sync::atomic::Ordering::Relaxed) {
                let peer_count = self.all_peers().len();
                if peer_count < MIN_PEERS {
                    if state.connected {
                        warn!("Lost connection to gossip network, reconnecting...");
                        state.connected = false;
                    }
                } else if !state.connected {
                    info!("Connected to gossip network with {} peers", peer_count);
                    state.connected = true;
                }

                let peers_changed = peer_count != state.last_peer_count;

                for (peer, _) in self.all_peers() {
                    let is_me = peer.pubkey() == &self.id();
                    let shred_ver = peer.shred_version();

                    // Update shred version served by JSONRPC if it's me and has changed
                    if is_me && shred_ver != 0 && shred_ver != state.last_shred_version {
                        info!(
                            "Got shred version {} -> {}",
                            state.last_shred_version, shred_ver
                        );
                        shred_version.store(shred_ver, std::sync::atomic::Ordering::SeqCst);
                        state.last_shred_version = shred_ver;
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
                    state.last_peer_count = peer_count;
                }

                match scraper.get_snapshot_hashes().await {
                    Ok(snapshot_hashes) => {
                        let (ttl_reached, hash_changed) = state.should_push(&snapshot_hashes);
                        if ttl_reached || hash_changed {
                            match (ttl_reached, hash_changed) {
                                (true, _) => info!(
                                    "TTL reached, last snapshot hash push was {}s ago",
                                    state.last_push.elapsed().as_secs()
                                ),
                                (_, true) => info!("Snapshot hashes changed"),
                                _ => (),
                            }
                            if let Err(e) = state.push_snapshot_hashes(self, snapshot_hashes) {
                                error!("{}", e);
                            }
                        }
                    }
                    Err(e) => error!("Failed to get snapshot hashes: {:?}", e),
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            info!("Gossip monitor service exited");
        })
    }
}

/// make_gossip_node() is a complete rewrite of solana_gossip::gossip_service::make_gossip_node
/// Accepts multiple entrypoints for redundancy
/// Different parameters:
/// * Entrypoints vector instead of a single entrypoint
/// * rpc_addr/rpc_pubsub_addr to add explicitly to ContactInfo
fn make_gossip_node(
    keypair: Keypair,
    entrypoints: Vec<SocketAddr>,
    exit: Arc<AtomicBool>,
    gossip_socket: &SocketAddr, // IP portion is advertised, port portion is used with hard coded UNSPECIFIED IP to listen on
    rpc_addr: Option<&SocketAddr>,
    rpc_pubsub_addr: Option<&SocketAddr>,
    shred_version: Option<u16>,
) -> (GossipService, Arc<ClusterInfo>) {
    let (node, gossip_socket, ip_echo) = {
        if shred_version.is_none() {
            // Issue #21 - Autodetecting the shred version is not yet implemented
            warn!(
                "No shred version provided, using 0. Expect problems joining the gossip network."
            );
        }

        // ClusterInfo::gossip_node() is an odd function.
        // * get_gossip_port() creates a gossip socket and an ip_echo socket and binds to them. It returns
        //   * The gossip_addr.port() that it bound both sockets to
        //   * The gossip_socket (UDP) ip_echo (TCP) sockets it bound to
        // * gossip_addr.ip():gossip_addr.port() is used to set the contact info
        /*
        fn gossip_node(pubkey, gossip_addr, shred_version){
            let bind_ip_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            let (port, (gossip_socket, ip_echo)) = Node::get_gossip_port(gossip_addr, VALIDATOR_PORT_RANGE, bind_ip_addr);
            let contact_info = Self::gossip_contact_info(id, SocketAddr::new(gossip_addr.ip(), port), shred_version);
        */
        let (mut node, gossip_socket, ip_echo) = ClusterInfo::gossip_node(
            keypair.pubkey(),
            &gossip_socket, // ip portion used to set contact info, IP hardcoded to UNSPECIFIED
            shred_version.unwrap_or(0),
        );

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
        (node, gossip_socket, ip_echo)
    };

    // Set up the IP echo server if a shred version is provided
    if let Some(my_shred_version) = shred_version {
        ip_echo::create_ip_echo_server(ip_echo, my_shred_version);

        // Test the IP echo server
        /*
            let gossip_port = gossip_socket.local_addr().unwrap().port();
            let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gossip_port);
            if let Ok(version) = ip_echo::ip_echo_client(test_addr) {
                info!("IP echo server test successful, got shred version: {}", version);
            } else {
                warn!("IP echo server test failed");
            }
        */
    } else {
        warn!("No shred version provided, not setting up IP echo server");
    }

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

pub async fn start_gossip_client(
    resolved: &ResolvedConfig,
    scraper: Arc<MetadataScraper>,
    exit: Arc<AtomicBool>,
    num_peers: Arc<AtomicI64>,
    shred_version: Arc<AtomicU16>,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    let node_keypair = read_keypair_file(&resolved.keypair_path).unwrap_or_else(|err| {
        warn!(
            "{} not found, generating new keypair: {}",
            resolved.keypair_path, err
        );
        Keypair::new()
    });
    info!("Our pubkey: {}", node_keypair.pubkey());

    // Start gossip service
    let gossip_addr = &SocketAddr::new(resolved.public_ip, resolved.gossip_port); // public_ip advertised, port portion is used with hard coded UNSPECIFIED listen IP
    let rpc_addr = &SocketAddr::new(resolved.public_ip, resolved.rpc_port);
    let rpc_pubsub_addr = &SocketAddr::new(resolved.public_ip, resolved.rpc_port + 1);
    info!(
        "Starting gossip service, reporting gossip {:?}, RPC {:?}",
        gossip_addr, rpc_addr
    );
    let (gossip_service, cluster_info) = make_gossip_node(
        node_keypair,
        resolved.entrypoints.clone(),
        exit.clone(),
        gossip_addr,
        Some(rpc_addr),        // public_ip:rpc_port
        Some(rpc_pubsub_addr), // public_ip:rpc_port+1
        resolved.shred_version,
    );
    info!("Started gossip service");

    info!("Starting monitor service...");
    let monitor_handle = tokio::spawn({
        let cluster_info = cluster_info.clone();
        let scraper = scraper.clone();
        let exit = exit.clone();
        let num_peers = num_peers.clone();
        let shred_version = shred_version.clone();
        async move {
            cluster_info
                .monitor_gossip(scraper, exit, num_peers, shred_version)
                .await;
        }
    });
    info!("Started monitor service");

    let gossip_handle = tokio::spawn(async move {
        gossip_service.join().unwrap();
    });

    Ok((monitor_handle, gossip_handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_decoding() {
        // Test empty hash
        let result = decode_hash!("");
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg, "string decoded to wrong size for hash");

        // Test valid base58-encoded hash
        let valid_hash_str = "BFz7BCSiUskXVu6VJy9UVvi3bfQryhFxSSQ24cF8Rsnr";
        let valid_hash = decode_hash!(valid_hash_str).unwrap();
        assert_eq!(valid_hash.as_ref().len(), 32);
        // Verify the hash value is correct by checking the base58 encoding
        assert_eq!(
            bs58::encode(valid_hash.as_ref()).into_string(),
            valid_hash_str
        );

        // Test invalid base58-encoded hash
        let invalid_hash_str2 = "7fK9DcRjWmXpLqNtYvBwEaZxHkMlPjQn";
        let result = decode_hash!(invalid_hash_str2);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg, "failed to decoded string to hash");

        // Test another invalid base58-encoded hash
        let invalid_hash_str = "too_short";
        let result = decode_hash!(invalid_hash_str);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg, "failed to decoded string to hash");
    }
}

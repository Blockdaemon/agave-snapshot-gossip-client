use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16};
use std::sync::Arc;
use std::time::Duration;

use bincode;
use log::{debug, info, warn};
use serde::de::{self, Deserialize as DeserializeTrait};
use serde::{Deserialize, Serialize};
use solana_gossip::cluster_info::ClusterInfo;
use solana_gossip::contact_info::ContactInfo;
use solana_gossip::gossip_service::GossipService;
use solana_sdk::signature::{Keypair, Signer};
use solana_streamer::socket::SocketAddrSpace;
use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub fn default_on_eof<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let value = DeserializeTrait::deserialize(deserializer);
    match value {
        Ok(value) => Ok(value),
        Err(err) => {
            if err.to_string().contains("EOF") {
                Ok(T::default())
            } else {
                Err(err)
            }
        }
    }
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
                        info!("Got shred version {} -> {}", last_shred_version, shred_ver);
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

/// make_gossip_node() is a complete rewrite of solana_gossip::gossip_service::make_gossip_node
/// Accepts multiple entrypoints for redundancy
/// Different parameters:
/// * Entrypoints vector instead of a single entrypoint
/// * rpc_addr/rpc_pubsub_addr to add explicitly to ContactInfo
pub fn make_gossip_node(
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
        create_ip_echo_server(ip_echo, my_shred_version);

        // Test the IP echo server
        /*
            let gossip_port = gossip_socket.local_addr().unwrap().port();
            let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gossip_port);
            if let Ok(version) = ip_echo_client(test_addr) {
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

// this is our own implementation of the ip echo server
const HEADER_LENGTH: usize = 4;
const DEFAULT_IP_ECHO_SERVER_THREADS: usize = 2;
const MAX_PORT_COUNT_PER_MESSAGE: usize = 4;
const IP_ECHO_SERVER_RESPONSE_LENGTH: usize = 27; // Fixed length from Agave implementation

#[derive(Serialize, Deserialize, Default, Debug)]
struct IpEchoServerMessage {
    tcp_ports: [u16; MAX_PORT_COUNT_PER_MESSAGE],
    udp_ports: [u16; MAX_PORT_COUNT_PER_MESSAGE],
}

#[derive(Serialize, Deserialize, Debug)]
struct IpEchoServerResponse {
    address: IpAddr,
    #[serde(deserialize_with = "default_on_eof")]
    shred_version: Option<u16>,
}

fn create_ip_echo_server(ip_echo: Option<std::net::TcpListener>, shred_version: u16) {
    let _ip_echo_server = ip_echo.map(|tcp_listener| {
        info!(
            "Starting IP echo server on TCP {}",
            tcp_listener.local_addr().unwrap()
        );

        // Spawn multiple tasks in the existing runtime
        for _ in 0..DEFAULT_IP_ECHO_SERVER_THREADS {
            let tcp_listener = TcpListener::from_std(tcp_listener.try_clone().unwrap())
                .expect("Failed to convert std::TcpListener");
            tokio::spawn(async move {
                loop {
                    match tcp_listener.accept().await {
                        Ok((mut socket, peer_addr)) => {
                            let mut header = [0u8; HEADER_LENGTH];
                            if let Err(err) = socket.read_exact(&mut header).await {
                                info!("Failed to read header: {:?}", err);
                                continue;
                            }

                            // Read the message
                            let mut message_buf = vec![0u8; ip_echo_server_request_length()];
                            if let Err(err) = socket.read_exact(&mut message_buf).await {
                                info!("Failed to read message: {:?}", err);
                                continue;
                            }

                            let response = IpEchoServerResponse {
                                address: peer_addr.ip(),
                                shred_version: Some(shred_version),
                            };

                            // Pre-allocate buffer and write header
                            let mut bytes = vec![0u8; IP_ECHO_SERVER_RESPONSE_LENGTH];
                            // Write response after header
                            bincode::serialize_into(&mut bytes[HEADER_LENGTH..], &response)
                                .unwrap();

                            if let Err(err) = socket.write_all(&bytes).await {
                                info!("session failed: {:?}", err);
                            }
                            // Wait for client to close the connection
                            let _ = socket.read(&mut [0u8; 1]).await;
                        }
                        Err(err) => warn!("listener accept failed: {:?}", err),
                    }
                }
            });
        }
    });
}

fn ip_echo_server_request_length() -> usize {
    bincode::serialized_size(&IpEchoServerMessage::default()).unwrap() as usize
}

pub async fn ip_echo_client(addr: SocketAddr) -> Result<u16, Box<dyn std::error::Error>> {
    let mut socket = tokio::net::TcpStream::connect(addr).await?;

    // Send the 4-byte header
    socket.write_all(&[0u8; 4]).await?;

    // Read the 2-byte shred version
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;

    // Convert bytes to u16
    let shred_version = u16::from_le_bytes(buf);
    Ok(shred_version)
}

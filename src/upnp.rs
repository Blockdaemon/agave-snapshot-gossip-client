// mostly does what easy-upnp does, but without the dependency on easy-upnp, so we can add a timeout to igd::search_gateway
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Result};
use get_if_addrs;
use igd::{PortMappingProtocol, SearchOptions};
use log::{debug, info};

/// A composite key that uniquely identifies a port forwarding entry.
/// The lower 16 bits represent the port number, and bit 16 represents the protocol (0 for UDP, 1 for TCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PortKey(u32);

impl PortKey {
    /// Creates a new PortKey from a port and protocol combination.
    ///
    /// # Arguments
    /// * `port` - The port number (0-65535)
    /// * `protocol` - The protocol (UDP or TCP)
    fn new(port: u16, protocol: &PortMappingProtocol) -> Self {
        let protocol_bit = match protocol {
            PortMappingProtocol::UDP => 0,
            PortMappingProtocol::TCP => 1,
        };
        Self(((protocol_bit as u32) << 16) | (port as u32))
    }

    /// Extracts port and protocol from the PortKey.
    fn decode(&self) -> (u16, PortMappingProtocol) {
        let port = (self.0 & 0xFFFF) as u16;
        let protocol = if (self.0 >> 16) & 1 == 0 {
            PortMappingProtocol::UDP
        } else {
            PortMappingProtocol::TCP
        };
        (port, protocol)
    }
}

trait PortSetExt {
    fn insert_port(&mut self, port: u16, protocol: &PortMappingProtocol);
}

impl PortSetExt for HashSet<PortKey> {
    fn insert_port(&mut self, port: u16, protocol: &PortMappingProtocol) {
        self.insert(PortKey::new(port, protocol));
    }
}

lazy_static::lazy_static! {
    static ref FORWARDED_PORTS: Mutex<HashSet<PortKey>> = Mutex::new(HashSet::new());
}

/// Sets up UPnP port forwarding for the specified ports.
///
/// # Arguments
/// * `ports` - A vector of (port, protocol) pairs to forward
/// * `bind_addr` - The local address to bind to for gateway discovery
pub fn setup_port_forwarding(
    ports: Vec<(u16, PortMappingProtocol)>,
    bind_addr: Option<IpAddr>,
) -> Result<()> {
    let mut forwarded_ports = match FORWARDED_PORTS.lock() {
        Ok(guard) => guard,
        Err(e) => return Err(anyhow!("Failed to acquire lock: {}", e)),
    };

    let search_options = SearchOptions {
        timeout: Some(Duration::from_secs(5)),
        bind_addr: bind_addr
            .map(|addr| SocketAddr::new(addr, 0))
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        ..Default::default()
    };

    info!("Searching for UPnP gateway...");
    let gateway = match igd::search_gateway(search_options) {
        Ok(g) => g,
        Err(e) => return Err(anyhow!("Failed to discover gateway: {}", e)),
    };
    info!("Found UPnP gateway {}", gateway.addr);

    debug!("Discovering our local ip...");
    let local_ip = match bind_addr {
        Some(IpAddr::V4(ip)) => ip,
        Some(IpAddr::V6(_)) => return Err(anyhow!("IPv6 not supported for UPnP port forwarding")),
        None => {
            let ifaces = match get_if_addrs::get_if_addrs() {
                Ok(ifaces) => ifaces,
                Err(e) => return Err(anyhow!("Failed to get network interfaces: {}", e)),
            };
            ifaces
                .iter()
                .find_map(|iface| {
                    if !iface.is_loopback() && iface.ip().is_ipv4() {
                        match iface.ip() {
                            IpAddr::V4(ip) => Some(ip),
                            IpAddr::V6(_) => None,
                        }
                    } else {
                        None
                    }
                })
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
        }
    };

    for (port, protocol) in &ports {
        info!(
            "Attempting to forward port {} ({:?}) to {:?}...",
            port, protocol, local_ip
        );

        match gateway.add_port(
            *protocol,
            *port,
            SocketAddrV4::new(local_ip, *port),
            0,
            "solana-gossip",
        ) {
            Ok(()) => {
                info!("Forwarded port {} ({:?}) to {:?}", port, protocol, local_ip);
                forwarded_ports.insert_port(*port, protocol);
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to forward port {} ({:?}): {}",
                    port,
                    protocol,
                    e
                ))
            }
        }
    }

    Ok(())
}

/// Cleans up all UPnP port forwarding rules that were previously set up.
pub fn cleanup_port_forwarding() -> Result<()> {
    let mut ports = match FORWARDED_PORTS.lock() {
        Ok(guard) => guard,
        Err(e) => return Err(anyhow!("Failed to acquire lock: {}", e)),
    };

    if ports.is_empty() {
        return Ok(());
    }

    let search_options = SearchOptions {
        timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };

    info!("Searching for UPnP gateway...");
    let gateway = match igd::search_gateway(search_options) {
        Ok(g) => g,
        Err(e) => return Err(anyhow!("Failed to discover gateway: {}", e)),
    };
    info!("Found UPnP gateway {}", gateway.addr);

    let ports_to_remove: Vec<_> = ports.iter().copied().collect();
    for port_key in ports_to_remove {
        let (port, protocol) = port_key.decode();
        info!(
            "Removing port forwarding for port {} ({:?})...",
            port, protocol
        );

        match gateway.remove_port(protocol, port) {
            Ok(_) => {
                info!("Removed port forwarding for port {} ({:?})", port, protocol);
                ports.remove(&port_key);
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to remove port {} ({:?}): {}",
                    port,
                    protocol,
                    e
                ))
            }
        }
    }
    Ok(())
}

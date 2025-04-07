use easy_upnp::{add_ports, delete_ports, PortMappingProtocol, UpnpConfig};
use log::{error, info, warn};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

#[derive(Debug)]
pub struct UpnpError {
    errors: Vec<Box<dyn Error + Send + Sync>>,
}

impl UpnpError {
    fn new(errors: Vec<Box<dyn Error + Send + Sync>>) -> Self {
        Self { errors }
    }
}

impl fmt::Display for UpnpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let messages: Vec<_> = self.errors.iter().map(|e| e.to_string()).collect();
        write!(f, "{}", messages.join("; "))
    }
}

impl Error for UpnpError {}

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

/// Creates a UPnP configuration for a port and protocol.
pub fn make_upnp_config((port, protocol): (u16, PortMappingProtocol)) -> UpnpConfig {
    UpnpConfig {
        address: None,
        port,
        protocol,
        duration: 0,
        comment: "solana-gossip".to_string(),
    }
}

/// Sets up UPnP port forwarding for the specified ports.
///
/// # Arguments
/// * `ports` - A vector of (port, protocol) pairs to forward
pub fn setup_port_forwarding(ports: Vec<(u16, PortMappingProtocol)>) -> Result<(), UpnpError> {
    let mut forwarded_ports = match FORWARDED_PORTS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire lock for port forwarding: {}", e);
            return Err(UpnpError::new(vec![Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to acquire lock: {}", e),
            ))
                as Box<dyn Error + Send + Sync>]));
        }
    };

    let mut errors = Vec::new();
    for (port, protocol) in &ports {
        info!("Attempting to forward port {} ({:?})...", port, protocol);
        let config = make_upnp_config((*port, *protocol));

        let mut port_errors = Vec::new();
        for result in add_ports(vec![config]) {
            match result {
                Ok(_) => {
                    info!("Successfully forwarded port {} ({:?})", port, protocol);
                    forwarded_ports.insert_port(*port, protocol);
                    break;
                }
                Err(e) => {
                    warn!("Failed to forward port {} ({:?}): {}", port, protocol, e);
                    port_errors.push(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Port {} ({:?}): {}", port, protocol, e),
                    )) as Box<dyn Error + Send + Sync>);
                }
            }
        }

        if !port_errors.is_empty() {
            errors.push(Box::new(UpnpError::new(port_errors)) as Box<dyn Error + Send + Sync>);
        }
    }

    if !errors.is_empty() {
        Err(UpnpError::new(errors))
    } else {
        Ok(())
    }
}

/// Cleans up all UPnP port forwarding rules that were previously set up.
pub fn cleanup_port_forwarding() {
    let mut ports = match FORWARDED_PORTS.lock() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire lock for port cleanup: {}", e);
            return;
        }
    };

    let ports_to_remove: Vec<_> = ports.iter().copied().collect();
    for port_key in ports_to_remove {
        let (port, protocol) = port_key.decode();
        info!(
            "Removing port forwarding for port {} ({:?})...",
            port, protocol
        );

        let config = make_upnp_config((port, protocol));
        for result in delete_ports(vec![config]) {
            match result {
                Ok(_) => {
                    info!(
                        "Successfully removed port forwarding for port {} ({:?})",
                        port, protocol
                    );
                    ports.remove(&port_key);
                }
                Err(e) => error!(
                    "Failed to remove port forwarding for port {} ({:?}): {}",
                    port, protocol, e
                ),
            }
        }
    }
}

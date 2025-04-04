use easy_upnp::{add_ports, delete_ports, PortMappingProtocol, UpnpConfig};
use log::{error, info};
use std::collections::HashSet;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref FORWARDED_PORTS: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
}

fn make_port_key(port: u16, protocol: &PortMappingProtocol) -> u32 {
    let protocol_bit = match protocol {
        PortMappingProtocol::UDP => 0,
        PortMappingProtocol::TCP => 1,
    };
    ((protocol_bit as u32) << 16) | (port as u32)
}

pub fn make_upnp_config((port, protocol): (u16, PortMappingProtocol)) -> UpnpConfig {
    UpnpConfig {
        address: None,
        port,
        protocol,
        duration: 0,
        comment: "solana-gossip".to_string(),
    }
}

pub fn setup_port_forwarding(ports: Vec<(u16, PortMappingProtocol)>) {
    info!("Attempting UPnP port forwarding for {:?}...", ports);
    let mut forwarded_ports = FORWARDED_PORTS.lock().unwrap();

    for port_config in ports {
        let config = make_upnp_config(port_config);
        for result in add_ports(vec![config]) {
            match result {
                Ok(_) => {
                    info!(
                        "  - Successfully forwarded {:?} port {}",
                        port_config.1, port_config.0
                    );
                    forwarded_ports.insert(make_port_key(port_config.0, &port_config.1));
                }
                Err(e) => error!("  - Failed to forward port: {}", e),
            }
        }
    }
}

pub fn cleanup_port_forwarding() {
    let mut ports = FORWARDED_PORTS.lock().unwrap();
    let ports_to_remove: Vec<_> = ports.iter().copied().collect();
    for port_key in ports_to_remove {
        let port = (port_key & 0xFFFF) as u16;
        let protocol = if (port_key >> 16) & 1 == 0 {
            PortMappingProtocol::UDP
        } else {
            PortMappingProtocol::TCP
        };
        info!(
            "Removing UPnP port forwarding for {:?} {}...",
            protocol, port
        );
        let config = make_upnp_config((port, protocol));
        for result in delete_ports(vec![config]) {
            match result {
                Ok(_) => {
                    info!("  - Successfully removed port {:?} {}", protocol, port);
                    ports.remove(&port_key);
                }
                Err(e) => error!("  - Failed to remove port {:?} {}: {}", protocol, port, e),
            }
        }
    }
}

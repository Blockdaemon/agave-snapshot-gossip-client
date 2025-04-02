use easy_upnp::{add_ports, delete_ports, PortMappingProtocol, UpnpConfig};
use std::collections::HashSet;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref FORWARDED_PORTS: Mutex<HashSet<u16>> = Mutex::new(HashSet::new());
}

pub fn make_upnp_config(port: u16) -> UpnpConfig {
    UpnpConfig {
        address: None,
        port,
        protocol: PortMappingProtocol::UDP,
        duration: 0,
        comment: "solana-gossip".to_string(),
    }
}

pub fn setup_port_forwarding(ports: Vec<u16>) {
    println!("Attempting UPnP port forwarding...");
    let mut forwarded_ports = FORWARDED_PORTS.lock().unwrap();

    for port in ports {
        let config = make_upnp_config(port);
        for result in add_ports(vec![config]) {
            match result {
                Ok(_) => {
                    println!("  - Successfully forwarded UDP port {}", port);
                    forwarded_ports.insert(port);
                }
                Err(e) => println!("  - Failed to forward port: {}", e),
            }
        }
    }
}

pub fn cleanup_port_forwarding() {
    println!("Removing UPnP port forwarding...");
    let mut ports = FORWARDED_PORTS.lock().unwrap();
    let ports_to_remove: Vec<u16> = ports.iter().copied().collect();
    for port in ports_to_remove {
        let config = make_upnp_config(port);
        for result in delete_ports(vec![config]) {
            match result {
                Ok(_) => {
                    println!("  - Successfully removed UDP port {}", port);
                    ports.remove(&port);
                }
                Err(e) => println!("  - Failed to remove port: {}", e),
            }
        }
    }
}

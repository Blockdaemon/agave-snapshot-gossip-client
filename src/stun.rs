use std::net::IpAddr;

use anyhow::Result;
use dns_lookup::lookup_host;
use log::{error, info};
use stun_client::*;

pub struct StunClient {
    stun_server: String,
    cached_addr: Option<IpAddr>,
}

#[derive(Debug)]
pub enum StunError {
    ClientCreation(String),
    BindingRequest(String),
    AddressExtraction(String),
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StunError::ClientCreation(e) => write!(f, "Client creation failed: {}", e),
            StunError::BindingRequest(e) => write!(f, "Binding request failed: {}", e),
            StunError::AddressExtraction(e) => write!(f, "Address extraction failed: {}", e),
        }
    }
}

impl StunClient {
    pub fn new(stun_server: String) -> Self {
        // Resolve DNS if hostname is used
        let stun_host = stun_server.split(':').next().unwrap();
        let stun_ip = lookup_host(stun_host)
            .unwrap_or_else(|e| {
                error!("Failed to resolve STUN server hostname: {}", e);
                std::process::exit(1);
            })
            .into_iter()
            .find(|ip| ip.is_ipv4())
            .unwrap_or_else(|| {
                error!("No IPv4 addresses found for STUN server");
                std::process::exit(1);
            });

        let port = stun_server.split(':').nth(1).unwrap();
        let resolved_server = format!("{}:{}", stun_ip, port);

        Self {
            stun_server: resolved_server,
            cached_addr: None,
        }
    }

    pub async fn get_public_ip(&mut self, no_cache: bool) -> Result<IpAddr, StunError> {
        if !no_cache && self.cached_addr.is_some() {
            if let Some(ip) = self.cached_addr {
                info!("Using cached public IP: {}", ip);
                return Ok(ip);
            }
        }

        info!("Using STUN server: {}", self.stun_server);
        let mut client = Client::new("0.0.0.0:0", None)
            .await
            .map_err(|e| StunError::ClientCreation(e.to_string()))?;

        let res = client
            .binding_request(&self.stun_server, None)
            .await
            .map_err(|e| StunError::BindingRequest(e.to_string()))?;

        let addr = Attribute::get_xor_mapped_address(&res)
            .ok_or_else(|| StunError::AddressExtraction("No XOR mapped address found".into()))?;

        let ip = addr.ip();
        if !no_cache {
            self.cached_addr = Some(ip);
        }
        info!("STUN detected public IP: {}", ip);
        Ok(ip)
    }
}

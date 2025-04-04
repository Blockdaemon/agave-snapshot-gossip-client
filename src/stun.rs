use dns_lookup::lookup_host;
use log::{error, info};
use std::net::IpAddr;
use stun_client::*;

pub struct StunClient {
    stun_server: String,
    cached_addr: Option<IpAddr>,
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

    async fn get_public_addr_with_stun(&self) -> Option<IpAddr> {
        info!("Using STUN server: {}", self.stun_server);
        let mut client = Client::new("0.0.0.0:0", None).await.ok()?;
        let res = client.binding_request(&self.stun_server, None).await.ok()?;
        let ip = Attribute::get_xor_mapped_address(&res).map(|addr| addr.ip());
        if let Some(ip) = ip {
            info!("STUN detected public IP: {}", ip);
        }
        ip
    }

    pub async fn get_public_addr(&mut self) -> Result<IpAddr, std::io::Error> {
        if let Some(ip) = self.cached_addr {
            return Ok(ip);
        }

        let ip = self.get_public_addr_with_stun().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to get public address from STUN server",
            )
        })?;
        self.cached_addr = Some(ip);
        Ok(ip)
    }
}

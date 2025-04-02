use dns_lookup::lookup_host;
use stun_client::*;
use tokio::runtime::Runtime;

pub struct StunClient {
    runtime: Runtime,
    stun_server: String,
    cached_addr: Option<std::net::IpAddr>,
}

impl StunClient {
    pub fn new(stun_server: String) -> Self {
        // Resolve DNS if hostname is used
        let stun_host = stun_server.split(':').next().unwrap();
        let stun_ip = lookup_host(stun_host)
            .expect("Failed to resolve STUN server hostname")
            .into_iter()
            .find(|ip| ip.is_ipv4())
            .expect("No IPv4 addresses found for STUN server");

        let port = stun_server.split(':').nth(1).unwrap();
        let resolved_server = format!("{}:{}", stun_ip, port);

        Self {
            runtime: Runtime::new().expect("Failed to create Tokio runtime"),
            stun_server: resolved_server,
            cached_addr: None,
        }
    }

    async fn get_public_addr_with_stun(&self) -> Option<std::net::IpAddr> {
        println!("Using STUN server: {}", self.stun_server);
        let mut client = Client::new("0.0.0.0:0", None).await.ok()?;
        let res = client.binding_request(&self.stun_server, None).await.ok()?;
        let ip = Attribute::get_xor_mapped_address(&res).map(|addr| addr.ip());
        if let Some(ip) = ip {
            println!("STUN detected public IP: {}", ip);
        }
        ip
    }

    pub fn get_public_addr(&mut self) -> Result<std::net::IpAddr, std::io::Error> {
        if let Some(ip) = self.cached_addr {
            return Ok(ip);
        }

        let ip = self
            .runtime
            .block_on(self.get_public_addr_with_stun())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to get public address from STUN server",
                )
            })?;
        self.cached_addr = Some(ip);
        Ok(ip)
    }
}

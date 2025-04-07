use crate::constants::{
    DEFAULT_GOSSIP_PORT, DEFAULT_RPC_PORT, DEFAULT_STUN_PORT, DEFAULT_TESTNET_ENTRYPOINTS,
    DEFAULT_TESTNET_GENESIS_HASH, DEFAULT_TESTNET_SHRED_VERSION,
};
use crate::stun::{StunClient, StunError};
use dns_lookup::lookup_host;
use log::{error, warn};
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_keypair_path")]
    pub keypair_path: String,
    pub stun_server: Option<String>,
    pub entrypoints: Option<Vec<String>>,
    pub genesis_hash: Option<String>,
    pub shred_version: Option<u16>,
    pub public_addr: Option<String>,
    pub enable_upnp: Option<bool>,
    pub rpc_listen: Option<String>,
    pub storage_server: Option<String>,
}

fn default_keypair_path() -> String {
    "keypair.json".to_string()
}

#[derive(Clone)]
pub struct ResolvedConfig {
    pub entrypoints: Vec<SocketAddr>,
    pub genesis_hash: String,
    pub shred_version: u16,
    pub rpc_listen: SocketAddr,
    pub public_addr: IpAddr,
    pub enable_upnp: bool,
    pub storage_server: String,
}

#[derive(Debug)]
pub enum ConfigError {
    StunError(StunError),
    InvalidAddress(String),
    DnsLookupError(String),
    ParseError(String),
}

impl std::error::Error for ConfigError {}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::StunError(e) => write!(f, "STUN error: {}", e),
            ConfigError::InvalidAddress(e) => write!(f, "Invalid address: {}", e),
            ConfigError::DnsLookupError(e) => write!(f, "DNS lookup error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl Config {
    fn parse_addr(addr_str: &str, default_port: u16) -> Result<SocketAddr, ConfigError> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        let (host, port) = match parts.len() {
            1 => (parts[0], default_port),
            2 => (
                parts[0],
                parts[1]
                    .parse()
                    .map_err(|e| ConfigError::ParseError(format!("Invalid port: {}", e)))?,
            ),
            _ => return Err(ConfigError::InvalidAddress("Invalid address format".into())),
        };

        let ip = lookup_host(host)
            .map_err(|e| ConfigError::DnsLookupError(e.to_string()))?
            .into_iter()
            .next()
            .ok_or_else(|| ConfigError::DnsLookupError("No IP addresses found".into()))?;

        Ok(SocketAddr::new(ip, port))
    }

    pub async fn get_external_ip_with_stun(&self) -> Result<IpAddr, StunError> {
        let stun_server = self
            .stun_server
            .clone()
            .unwrap_or_else(|| "stun.l.google.com".to_string());

        let stun_port = if stun_server.contains(':') {
            let parts: Vec<&str> = stun_server.split(':').collect();
            parts[1].parse().unwrap_or(DEFAULT_STUN_PORT)
        } else {
            DEFAULT_STUN_PORT
        };

        let stun_host = stun_server.split(':').next().unwrap();
        let stun_server = format!("{}:{}", stun_host, stun_port);
        let mut stun_client = StunClient::new(stun_server);

        stun_client.get_public_ip(false).await
    }

    pub async fn resolve(&self) -> Result<ResolvedConfig, ConfigError> {
        let public_addr = match &self.public_addr {
            Some(addr) => addr
                .parse()
                .map_err(|e| ConfigError::ParseError(format!("Invalid public address: {}", e)))?,
            None => {
                warn!("No public_addr in config, attempting to discover...");
                self.get_external_ip_with_stun()
                    .await
                    .map_err(ConfigError::StunError)?
            }
        };

        let entrypoints = self
            .entrypoints
            .clone()
            .unwrap_or_else(|| {
                DEFAULT_TESTNET_ENTRYPOINTS
                    .iter()
                    .map(|&s| s.to_string())
                    .collect()
            })
            .into_iter()
            .map(|addr| Self::parse_addr(&addr, DEFAULT_GOSSIP_PORT))
            .collect::<Result<Vec<_>, _>>()?;

        let enable_upnp = self.enable_upnp.unwrap_or(false);

        let rpc_listen = self
            .rpc_listen
            .as_ref()
            .map(|addr| Self::parse_addr(addr, DEFAULT_RPC_PORT))
            .unwrap_or_else(|| {
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    DEFAULT_RPC_PORT,
                ))
            })?;

        Ok(ResolvedConfig {
            entrypoints,
            genesis_hash: self
                .genesis_hash
                .clone()
                .unwrap_or_else(|| DEFAULT_TESTNET_GENESIS_HASH.to_string()),
            shred_version: self.shred_version.unwrap_or(DEFAULT_TESTNET_SHRED_VERSION),
            rpc_listen,
            public_addr,
            enable_upnp,
            storage_server: self.storage_server.clone().unwrap_or_default(),
        })
    }
}

pub fn load_config() -> Config {
    match fs::read_to_string("config.toml") {
        Ok(config_str) => {
            let mut config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
                error!("Failed to parse config.toml: {}", e);
                std::process::exit(1);
            });
            config.enable_upnp.get_or_insert(false);
            config
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("No config.toml found, using defaults");
            Config {
                keypair_path: String::new(),
                entrypoints: None,
                stun_server: None,
                public_addr: None,
                enable_upnp: None,
                rpc_listen: None,
                genesis_hash: None,
                shred_version: None,
                storage_server: None,
            }
        }
        Err(e) => panic!("Error reading config.toml: {}", e),
    }
}

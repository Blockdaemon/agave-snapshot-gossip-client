use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use dns_lookup::lookup_host;
use hyper::Uri;
use log::{error, warn};
use serde::Deserialize;

use crate::constants::{
    DEFAULT_CONFIG_PATH, DEFAULT_GOSSIP_PORT, DEFAULT_KEYPAIR_PATH, DEFAULT_LISTEN_IP,
    DEFAULT_RPC_PORT, DEFAULT_STUN_PORT, DEFAULT_STUN_SERVER, TESTNET_ENTRYPOINTS,
};
use crate::stun::{StunClient, StunError};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keypair_path: Option<String>,

    // What network to connect to
    pub entrypoints: Option<Vec<String>>,
    pub expected_genesis_hash: Option<String>,
    pub shred_version: Option<u16>,

    // What local IP to bind to and listen on
    pub listen_ip: Option<String>,

    // What public IP to advertise, or how to discover it
    pub public_ip: Option<String>,
    pub stun_server: Option<String>,

    // What gossip and RPC ports to listen on and advertise
    pub gossip_port: Option<u16>,
    pub rpc_port: Option<u16>,

    // Punch holes in the firewall
    pub enable_upnp: Option<bool>,

    // Where to redirect/proxy HTTP GET requests to
    pub storage_path: Option<String>,

    // Reverse proxy HTTP GET requests instead of redirecting
    pub enable_proxy: Option<bool>,
}

#[derive(Clone)]
pub struct ResolvedConfig {
    pub keypair_path: String,
    pub entrypoints: Vec<SocketAddr>,
    pub shred_version: Option<u16>,
    pub expected_genesis_hash: Option<String>,
    pub listen_ip: IpAddr,
    pub public_ip: IpAddr,
    pub gossip_port: u16,
    pub rpc_port: u16,
    pub enable_upnp: bool,
    pub storage_path: Option<Uri>,
    pub enable_proxy: bool,
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
            .unwrap_or_else(|| DEFAULT_STUN_SERVER.to_string());

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
        let public_ip = match &self.public_ip {
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
            .unwrap_or_else(|| TESTNET_ENTRYPOINTS.iter().map(|&s| s.to_string()).collect())
            .into_iter()
            .map(|addr| Self::parse_addr(&addr, DEFAULT_GOSSIP_PORT))
            .collect::<Result<Vec<_>, _>>()?;

        let storage_path = match self.storage_path.as_deref() {
            None => None,
            Some(s) => Some(Uri::from_str(s).map_err(|e| {
                ConfigError::ParseError(format!("Invalid storage path URL: {}", e))
            })?),
        };

        Ok(ResolvedConfig {
            keypair_path: self
                .keypair_path
                .clone()
                .unwrap_or_else(|| DEFAULT_KEYPAIR_PATH.to_string()),
            entrypoints,
            expected_genesis_hash: self.expected_genesis_hash.clone(),
            shred_version: self.shred_version.clone(),
            listen_ip: self
                .listen_ip
                .as_ref()
                .and_then(|ip| ip.parse().ok())
                .unwrap_or(DEFAULT_LISTEN_IP),
            public_ip,
            gossip_port: self.gossip_port.unwrap_or(DEFAULT_GOSSIP_PORT),
            rpc_port: self.rpc_port.unwrap_or(DEFAULT_RPC_PORT),
            enable_upnp: self.enable_upnp.unwrap_or(false),
            storage_path,
            enable_proxy: self.enable_proxy.unwrap_or(false),
        })
    }
}

pub fn load_config(config_path: Option<&str>) -> Config {
    let path = config_path.unwrap_or(DEFAULT_CONFIG_PATH);
    match fs::read_to_string(path) {
        Ok(config_str) => {
            let mut config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
                error!("Failed to parse {}: {}", path, e);
                std::process::exit(1);
            });
            config.enable_upnp.get_or_insert(false);
            config.enable_proxy.get_or_insert(false);
            config
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("No {} found, using defaults", path);
            Config {
                keypair_path: None,
                entrypoints: None,
                stun_server: None,
                public_ip: None,
                enable_upnp: None,
                listen_ip: None,
                gossip_port: None,
                rpc_port: None,
                expected_genesis_hash: None,
                shred_version: None,
                storage_path: None,
                enable_proxy: None,
            }
        }
        Err(e) => panic!("Error reading {}: {}", path, e),
    }
}

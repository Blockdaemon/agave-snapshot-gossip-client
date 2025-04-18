use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use dns_lookup::lookup_host;
use http::Uri;
use log::{debug, error, info, warn};
use serde::Deserialize;

// our local crates
use crate::constants::{
    DEFAULT_CONFIG_PATH, DEFAULT_GOSSIP_PORT, DEFAULT_KEYPAIR_PATH, DEFAULT_LISTEN_IP,
    DEFAULT_RPC_PORT, DEFAULT_STUN_PORT, DEFAULT_STUN_SERVER, DEVNET_ENTRYPOINTS,
    DEVNET_GENESIS_HASH, MAINNET_ENTRYPOINTS, MAINNET_GENESIS_HASH, TESTNET_ENTRYPOINTS,
    TESTNET_GENESIS_HASH,
};
use crate::stun::{StunClient, StunError};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keypair_path: Option<String>,

    // What network to connect to
    pub network: Option<String>, // "devnet", "testnet", or "mainnet"
    pub entrypoints: Option<Vec<String>>,
    pub expected_genesis_hash: Option<String>,
    pub shred_version: Option<u16>,

    // What local IP to bind to and listen on
    pub listen_ip: Option<String>,

    // What public IP to advertise, or how to discover it
    pub public_ip: Option<String>,
    pub enable_stun: Option<bool>,
    pub stun_server: Option<String>,

    // Disable gossip, what gossip and RPC ports to listen on and advertise
    pub disable_gossip: Option<bool>,
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
    pub disable_gossip: bool,
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
    IpEchoError(String),
}

impl std::error::Error for ConfigError {}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::StunError(e) => write!(f, "STUN error: {}", e),
            ConfigError::InvalidAddress(e) => write!(f, "Invalid address: {}", e),
            ConfigError::DnsLookupError(e) => write!(f, "DNS lookup error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
            ConfigError::IpEchoError(e) => write!(f, "IP echo error: {}", e),
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

        debug!("Attempting DNS lookup for host: {}", host);
        let ip = lookup_host(host)
            .map_err(|e| {
                error!("DNS lookup failed for host '{}': {}", host, e);
                ConfigError::DnsLookupError(e.to_string())
            })?
            .into_iter()
            .next()
            .ok_or_else(|| {
                error!("No IP addresses found for host '{}'", host);
                ConfigError::DnsLookupError("No IP addresses found".into())
            })?;

        debug!("Successfully resolved host '{}' to IP: {}", host, ip);
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

    pub async fn ip_echo(&self, entrypoints: &[SocketAddr]) -> Result<(IpAddr, u16), ConfigError> {
        let mut discovered_ip = None;
        let mut discovered_shred_version = None;
        let mut last_error = None;

        // Try each entrypoint with IP echo client
        for entrypoint in entrypoints {
            let request = crate::ip_echo::IpEchoServerMessage::new(&[], &[]);
            info!("IP echo request to {}: {:?}", entrypoint, request);
            match crate::ip_echo::ip_echo_client(*entrypoint, request).await {
                Ok((ip, shred_version)) => {
                    discovered_ip = Some(ip);
                    discovered_shred_version = Some(shred_version);
                    info!(
                        "IP echo response from {}: {:?} {:?}",
                        entrypoint, ip, shred_version
                    );
                    break;
                }
                Err(e) => {
                    warn!("IP echo failed for {}: {}", entrypoint, e);
                    last_error = Some(e);
                    continue;
                }
            }
        }

        match (discovered_ip, discovered_shred_version) {
            (Some(ip), Some(shred_version)) => Ok((ip, shred_version)),
            _ => Err(ConfigError::IpEchoError(
                last_error
                    .map(|e| format!("All entrypoints failed, last error: {}", e))
                    .unwrap_or_else(|| "Failed to discover public IP through IP echo".into()),
            )),
        }
    }

    pub async fn resolve(&self) -> Result<ResolvedConfig, ConfigError> {
        // Resolve entrypoints first since we need them for both IP echo and final config
        let mut resolved_entrypoints = Vec::new();
        let (entrypoint_strings, default_genesis_hash) = if let Some(network) = &self.network {
            match network.to_lowercase().as_str() {
                "devnet" => (
                    DEVNET_ENTRYPOINTS.iter().map(|&s| s.to_string()).collect(),
                    Some(DEVNET_GENESIS_HASH.to_string()),
                ),
                "testnet" => (
                    TESTNET_ENTRYPOINTS.iter().map(|&s| s.to_string()).collect(),
                    Some(TESTNET_GENESIS_HASH.to_string()),
                ),
                "mainnet" => (
                    MAINNET_ENTRYPOINTS.iter().map(|&s| s.to_string()).collect(),
                    Some(MAINNET_GENESIS_HASH.to_string()),
                ),
                _ => {
                    warn!("Unknown network: {}, using testnet", network);
                    (
                        TESTNET_ENTRYPOINTS.iter().map(|&s| s.to_string()).collect(),
                        Some(TESTNET_GENESIS_HASH.to_string()),
                    )
                }
            }
        } else {
            (
                self.entrypoints.clone().unwrap_or_else(|| {
                    TESTNET_ENTRYPOINTS.iter().map(|&s| s.to_string()).collect()
                }),
                None,
            )
        };

        for addr in entrypoint_strings {
            match Self::parse_addr(&addr, DEFAULT_GOSSIP_PORT) {
                Ok(socket_addr) => {
                    info!("Successfully resolved entrypoint: {}", addr);
                    resolved_entrypoints.push(socket_addr);
                }
                Err(e) => {
                    warn!("Failed to resolve entrypoint {}: {}", addr, e);
                    continue;
                }
            }
        }

        if resolved_entrypoints.is_empty() {
            return Err(ConfigError::DnsLookupError(
                "No valid entrypoints could be resolved".into(),
            ));
        }

        let (public_ip, discovered_shred_version) = {
            // First try IP echo to get public ip and shred version at the same time
            let ip_echo_result = self.ip_echo(&resolved_entrypoints).await;

            // If public_ip is configured, use that regardless of IP echo result
            // If we get ip echo result and user configured a public ip, compare them
            if let Some(addr) = &self.public_ip {
                let ip = addr.parse().map_err(|e| {
                    ConfigError::ParseError(format!("Invalid public address: {}", e))
                })?;
                if let Ok((echo_ip, _)) = &ip_echo_result {
                    if ip != *echo_ip {
                        error!(
                            "Configured public IP {} differs from IP echo result {}",
                            ip, echo_ip
                        );
                    }
                }
                (ip, ip_echo_result.ok().map(|(_, version)| version))
            } else {
                match ip_echo_result {
                    Ok((ip, shred_version)) => (ip, Some(shred_version)),
                    Err(e) => {
                        warn!("IP echo failed: {}", e);
                        if self.enable_stun.unwrap_or(false) {
                            (
                                self.get_external_ip_with_stun()
                                    .await
                                    .map_err(ConfigError::StunError)?,
                                None,
                            )
                        } else {
                            return Err(ConfigError::IpEchoError(
                                "Failed to discover public IP through IP echo and STUN is disabled"
                                    .into(),
                            ));
                        }
                    }
                }
            }
        };

        // Validate and resolve shred version:
        // - Error if both versions exist and differ
        // - Use whichever version is available
        // - Return None if neither version is available
        let shred_version = match (discovered_shred_version, self.shred_version) {
            (Some(discovered), Some(configured)) if discovered != configured => {
                return Err(ConfigError::ParseError(format!(
                    "Shred version mismatch: {} from ip echo, {} from config",
                    discovered, configured
                )));
            }
            (Some(discovered), _) => Some(discovered),
            (_, configured) => configured,
        };

        let storage_path = Some(
            self.storage_path
                .as_deref()
                .map(|s| {
                    // Try to parse as URI first to check if it has a valid scheme
                    if let Ok(uri) = Uri::from_str(s) {
                        if uri.scheme_str().is_some() {
                            // If it's already a valid URI with a scheme, use it as-is
                            return s.to_string();
                        }
                    }

                    if s.starts_with('/') {
                        // If it's an absolute path, convert to file URI
                        format!("file://localhost{}", s)
                    } else {
                        // If it's a relative path, join with current dir and convert to file URI
                        let path = std::env::current_dir()
                            .unwrap()
                            .join(s)
                            .to_string_lossy()
                            .to_string();
                        format!("file://localhost{}", path)
                    }
                })
                .unwrap_or_else(|| {
                    // Default to "storage" in current directory
                    let path = std::env::current_dir()
                        .unwrap()
                        .join("storage")
                        .to_string_lossy()
                        .to_string();
                    format!("file://localhost{}", path)
                }),
        );
        let storage_path = storage_path
            .map(|s| {
                Uri::from_str(&s).map_err(|e| {
                    ConfigError::ParseError(format!("Invalid storage path URL: {}", e))
                })
            })
            .transpose()?;

        // Use the network's default genesis hash if none is specified
        let expected_genesis_hash = self.expected_genesis_hash.clone().or(default_genesis_hash);

        Ok(ResolvedConfig {
            keypair_path: self
                .keypair_path
                .clone()
                .unwrap_or_else(|| DEFAULT_KEYPAIR_PATH.to_string()),
            entrypoints: resolved_entrypoints,
            expected_genesis_hash,
            shred_version,
            listen_ip: self
                .listen_ip
                .as_ref()
                .and_then(|ip| ip.parse().ok())
                .unwrap_or(DEFAULT_LISTEN_IP),
            public_ip,
            disable_gossip: self.disable_gossip.unwrap_or(false),
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
            config.enable_stun.get_or_insert(false);
            config.enable_upnp.get_or_insert(false);
            config.enable_proxy.get_or_insert(false);
            config
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("No {} found, using defaults", path);
            Config {
                keypair_path: None,
                network: None,
                entrypoints: None,
                enable_stun: None,
                stun_server: None,
                public_ip: None,
                enable_upnp: None,
                listen_ip: None,
                disable_gossip: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::tempdir;

    fn make_test_config(storage_path: Option<String>) -> Config {
        Config {
            keypair_path: None,
            network: None,
            entrypoints: None,
            expected_genesis_hash: None,
            shred_version: None,
            listen_ip: None,
            public_ip: None,
            enable_stun: None,
            stun_server: None,
            disable_gossip: None,
            gossip_port: None,
            rpc_port: None,
            enable_upnp: None,
            storage_path,
            enable_proxy: None,
        }
    }

    #[tokio::test]
    async fn test_storage_path_resolution() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        // Create the storage directory first
        let storage_dir = temp_dir.path().join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let canonical_storage_path = storage_dir
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // Helper function to test a storage path
        let test_path =
            async move |input: Option<String>, expected_uri: &str, expected_path: &str| {
                let config = make_test_config(input);
                let resolved = config.resolve().await.unwrap();
                let uri = resolved.storage_path.unwrap();
                assert_eq!(uri.to_string(), expected_uri);
                assert_eq!(uri.path(), expected_path);
            };

        // Test absolute paths
        test_path(
            Some("/tmp/testpath/storage".to_string()),
            "file://localhost/tmp/testpath/storage",
            "/tmp/testpath/storage",
        )
        .await;

        test_path(
            Some("/tmp/test.path/storage".to_string()),
            "file://localhost/tmp/test.path/storage",
            "/tmp/test.path/storage",
        )
        .await;

        test_path(
            Some("/absolute/storage".to_string()),
            "file://localhost/absolute/storage",
            "/absolute/storage",
        )
        .await;

        // Test relative and default paths
        test_path(
            Some("storage".to_string()),
            &format!("file://localhost{}", canonical_storage_path),
            &canonical_storage_path,
        )
        .await;

        test_path(
            None,
            &format!("file://localhost{}", canonical_storage_path),
            &canonical_storage_path,
        )
        .await;

        // Test URL paths with various schemes
        test_path(
            Some("https://example.com".to_string()),
            "https://example.com/",
            "/",
        )
        .await;

        test_path(
            Some("http://example.com/storage".to_string()),
            "http://example.com/storage",
            "/storage",
        )
        .await;

        // Test other common schemes
        test_path(
            Some("ftp://example.com/files".to_string()),
            "ftp://example.com/files",
            "/files",
        )
        .await;

        test_path(
            Some("s3://bucket/path".to_string()),
            "s3://bucket/path",
            "/path",
        )
        .await;

        // Test domain-only URLs with trailing slash
        test_path(
            Some("https://example.com".to_string()),
            "https://example.com/",
            "/",
        )
        .await;

        test_path(Some("s3://bucket".to_string()), "s3://bucket/", "/").await;

        // Verify scheme handling
        let config = make_test_config(Some("https://example.com".to_string()));
        let resolved = config.resolve().await.unwrap();
        let uri = resolved.storage_path.unwrap();
        assert_eq!(uri.scheme_str(), Some("https"));

        let config = make_test_config(Some("/local/path".to_string()));
        let resolved = config.resolve().await.unwrap();
        let uri = resolved.storage_path.unwrap();
        assert_eq!(uri.scheme_str(), Some("file"));

        env::set_current_dir(original_dir).unwrap();
    }
}

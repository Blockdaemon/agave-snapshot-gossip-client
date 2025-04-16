use std::net::{IpAddr, Ipv4Addr};

use lazy_static::lazy_static;
use regex::Regex;

pub const DEFAULT_CONFIG_PATH: &str = "config.toml";
pub const DEFAULT_KEYPAIR_PATH: &str = "keypair.json";
pub const DEFAULT_GOSSIP_PORT: u16 = 8001;
pub const DEFAULT_LISTEN_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const DEFAULT_RPC_PORT: u16 = 8899;
pub const DEFAULT_STUN_SERVER: &str = "stun.l.google.com";
pub const DEFAULT_STUN_PORT: u16 = 3478;

pub const TESTNET_ENTRYPOINTS: &[&str] = &[
    "entrypoint.testnet.solana.com:8001",
    "entrypoint2.testnet.solana.com:8001",
    "entrypoint3.testnet.solana.com:8001",
];

// Unused, default values for both expected_genesis_hash and expected_shred_version are "None"
//pub const TESTNET_GENESIS_HASH: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";
//pub const TESTNET_SHRED_VERSION: u16 = 64475;

pub const DEFAULT_SNAPSHOT_INFO_PATH: &str = "latest.json";
// do not use commas in the user agent string, it causes problems with the mock server
pub const DEFAULT_SCRAPER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36";
pub const SOLANA_VALIDATOR_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
pub const DEFAULT_SCRAPER_CACHE_TTL_SECS: u64 = 5;
pub const DEFAULT_GOSSIP_CRDS_TTL_SECS: u64 = 15;

// Static regex pattern for snapshot requests
lazy_static! {
    pub static ref SNAPSHOT_REGEX: Regex = Regex::new(
        r"^/(genesis|snapshot|incremental-snapshot).*\.tar\.(bz2|zst|gz)$|^/latest\.json$"
    )
    .unwrap();
}

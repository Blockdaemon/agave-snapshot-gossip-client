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

pub const DEFAULT_TESTNET_ENTRYPOINTS: &[&str] = &[
    "entrypoint.testnet.solana.com:8001",
    "entrypoint2.testnet.solana.com:8001",
    "entrypoint3.testnet.solana.com:8001",
];

pub const DEFAULT_TESTNET_GENESIS_HASH: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";
pub const DEFAULT_TESTNET_SHRED_VERSION: u16 = 64475;

pub const DEFAULT_SNAPSHOT_INFO_PATH: &str = "latest.json";
pub const DEFAULT_SCRAPER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

lazy_static! {
    pub static ref SNAPSHOT_REGEX: Regex = Regex::new(
        r"^/(genesis|snapshot|incremental-snapshot).*\.tar\.(bz2|zst|gz)$|^/latest\.json$"
    )
    .unwrap();
}

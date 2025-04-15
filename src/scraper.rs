use std::error::Error;
use std::time::{Duration, Instant};

use http::Uri;
use log::{debug, error, info};
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;
use tokio::sync::RwLock;

use crate::constants::{
    DEFAULT_SCRAPER_CACHE_TTL_SECS, DEFAULT_SCRAPER_USER_AGENT, DEFAULT_SNAPSHOT_INFO_PATH,
};

const CACHE_DURATION: Duration = Duration::from_secs(DEFAULT_SCRAPER_CACHE_TTL_SECS);

#[derive(Debug)]
pub enum ScraperError {
    NetworkError(String),
    ParseError(String),
    NetworkMismatch(String),
}

impl std::error::Error for ScraperError {}

impl std::fmt::Display for ScraperError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ScraperError::NetworkError(e) => write!(f, "Network error: {}", e),
            ScraperError::ParseError(e) => write!(f, "Parse error: {}", e),
            ScraperError::NetworkMismatch(e) => write!(f, "Network mismatch: {}", e),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SnapshotInfo {
    pub solana_version: String,
    pub solana_feature_set: u32,
    pub genesis_hash: String,
    pub slot: u64,
    pub timestamp: u64,
    pub timestamp_human: String,
    pub status: String,
    pub uploaded_by: String,
    pub full_snapshot_hash: String,
    pub full_snapshot_slot: u64,
    pub full_snapshot_url: String,
    pub incremental_snapshot_hash: String,
    pub incremental_snapshot_slot: u64,
    pub incremental_snapshot_url: String,
}

#[derive(Debug, PartialEq)]
enum FileType {
    Genesis,
    Full,
    Incremental,
    Metadata,
}

impl FileType {
    fn from_path(path: &str) -> Result<Self, ScraperError> {
        if path.starts_with("/genesis") {
            Ok(Self::Genesis)
        } else if path.starts_with("/snapshot") {
            Ok(Self::Full)
        } else if path.starts_with("/incremental-snapshot") {
            Ok(Self::Incremental)
        } else if path.ends_with(".json") {
            Ok(Self::Metadata)
        } else {
            Err(ScraperError::ParseError(format!("Unknown path: {}", path)))
        }
    }
}

pub struct MetadataScraper {
    storage_path: Option<Uri>, // If not here, we'll always return the default snapshot info
    http_client: Client,
    expected_genesis_hash: Option<String>,
    cache: RwLock<(SnapshotInfo, Instant)>,
}

impl MetadataScraper {
    pub fn storage_path(&self) -> Option<&Uri> {
        self.storage_path.as_ref()
    }
    pub fn new(storage_path: Option<Uri>, expected_genesis_hash: Option<String>) -> Self {
        Self {
            http_client: Client::builder()
                .use_rustls_tls()
                .user_agent(DEFAULT_SCRAPER_USER_AGENT)
                .build()
                .unwrap(),
            storage_path,
            expected_genesis_hash: expected_genesis_hash.clone(),
            cache: RwLock::new((
                SnapshotInfo {
                    solana_version: "0.0.0".to_string(),
                    solana_feature_set: 0,
                    genesis_hash: expected_genesis_hash.unwrap_or("".to_string()), // use expected info as the default if provided
                    slot: 0,
                    timestamp: 0,
                    timestamp_human: "1970-01-01T00:00:00Z".to_string(),
                    status: "completed".to_string(),
                    uploaded_by: "unknown".to_string(),
                    full_snapshot_hash: "".to_string(),
                    full_snapshot_slot: 0,
                    full_snapshot_url: "".to_string(),
                    incremental_snapshot_hash: "".to_string(),
                    incremental_snapshot_slot: 0,
                    incremental_snapshot_url: "".to_string(),
                },
                Instant::now() - CACHE_DURATION * 2, // Make sure the cache starts expired
            )),
        }
    }

    fn join_urls(base: &Uri, path: &str) -> Result<String, ScraperError> {
        // Get base components
        let scheme = base.scheme_str().unwrap_or("http");
        let authority = base
            .authority()
            .map(|a| a.to_string())
            .ok_or_else(|| ScraperError::NetworkError("Missing authority in URI".to_string()))?;

        // Clean the path by removing leading slash if present
        let clean_path = path.strip_prefix('/').unwrap_or(path);

        // Join paths properly, handling trailing slashes
        let base_path = base.path();
        let joined_path = if base_path.ends_with('/') || base_path == "/" {
            format!("{}{}", base_path, clean_path)
        } else {
            format!("{}/{}", base_path, clean_path)
        };

        // Construct the final URL
        Ok(format!("{}://{}{}", scheme, authority, joined_path))
    }

    async fn fetch_snapshot_info(&self) -> Result<SnapshotInfo, ScraperError> {
        if self.storage_path.is_none() {
            return Err(ScraperError::NetworkError(
                "Storage path is not configured".to_string(),
            ));
        }
        let url = Self::join_urls(
            self.storage_path.as_ref().unwrap(),
            DEFAULT_SNAPSHOT_INFO_PATH,
        )?;
        info!("Fetching snapshot info from {}", url);
        let response = self.http_client.get(&url).send().await.map_err(|e| {
            ScraperError::NetworkError(format!(
                "Failed to fetch snapshot info from {}: {} (source: {:?})",
                url,
                e,
                e.source()
            ))
        })?;

        let body = response.text().await.map_err(|e| {
            ScraperError::NetworkError(format!("Failed to read response body {}: {}", url, e))
        })?;

        let info: SnapshotInfo = serde_json::from_str(&body).map_err(|e| {
            ScraperError::ParseError(format!(
                "Failed to parse snapshot info {}: {}\nBody: {}",
                url, e, body
            ))
        })?;

        if info.status != "completed" {
            return Err(ScraperError::NetworkError(format!(
                "Snapshot status is \"{}\", expected \"completed\"",
                info.status
            )));
        }

        if let Some(expected_genesis_hash) = &self.expected_genesis_hash {
            if info.genesis_hash != *expected_genesis_hash {
                return Err(ScraperError::NetworkMismatch(format!(
                    "Genesis hash is {}, expected {}",
                    info.genesis_hash, expected_genesis_hash
                )));
            }
        }

        Ok(info)
    }

    pub async fn get_cached_snapshot_info(&self) -> SnapshotInfo {
        let cache = self.cache.read().await;
        if cache.1.elapsed() < CACHE_DURATION {
            return cache.0.clone();
        }
        drop(cache);

        info!("Cache expired, fetching new snapshot info");
        match self.fetch_snapshot_info().await {
            Ok(info) => {
                let mut cache = self.cache.write().await;
                *cache = (info.clone(), Instant::now());
                info
            }
            Err(e) => {
                let cache = self.cache.read().await;
                let info = cache.0.clone();
                drop(cache);
                error!("Failed to fetch snapshot info, using stale info: {}", e);
                info
            }
        }
    }

    pub async fn build_uri(&self, request_uri: &Uri) -> Result<Uri, ScraperError> {
        let snapshot_type = FileType::from_path(request_uri.path()).unwrap();
        let request_path = request_uri.path();
        let uri_string = match snapshot_type {
            FileType::Full | FileType::Incremental => {
                // These provide a full URI to an arbitrary destination
                let info = self.get_cached_snapshot_info().await;
                debug!("{:?}", info);
                match snapshot_type {
                    FileType::Full => info.full_snapshot_url,
                    FileType::Incremental => info.incremental_snapshot_url,
                    _ => unreachable!(),
                }
            }
            FileType::Genesis | FileType::Metadata => {
                // These provide a path to a local file, prepend the storage path
                let storage_path = self.storage_path().ok_or_else(|| {
                    ScraperError::NetworkError("Storage path is not configured".to_string())
                })?;
                info!(
                    "Got storage path {:?} to use with {}",
                    storage_path, request_path
                );
                Self::join_urls(storage_path, request_path)?
            }
        };
        let final_uri = Uri::from_str(&uri_string)
            .map_err(|e| ScraperError::NetworkError(format!("Failed to parse URI: {}", e)))?;
        info!(
            "Converted {} ({}) to {}",
            request_uri, request_path, final_uri
        );
        Ok(final_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Uri;

    #[test]
    fn test_join_urls() {
        // Test cases for different base URLs and paths
        let test_cases = vec![
            // Base with trailing slash
            (
                "http://example.com:8899/storage/",
                "genesis.tar.gz",
                "http://example.com:8899/storage/genesis.tar.gz",
            ),
            // Base without trailing slash
            (
                "http://example.com:8899/storage",
                "genesis.tar.gz",
                "http://example.com:8899/storage/genesis.tar.gz",
            ),
            // Root path
            (
                "http://example.com:8899/",
                "genesis.tar.gz",
                "http://example.com:8899/genesis.tar.gz",
            ),
            // Empty path (just domain)
            (
                "http://example.com:8899",
                "genesis.tar.gz",
                "http://example.com:8899/genesis.tar.gz",
            ),
            // Path with leading slash
            (
                "http://example.com:8899/storage",
                "/genesis.tar.gz",
                "http://example.com:8899/storage/genesis.tar.gz",
            ),
            // Path with leading slash and base with trailing slash
            (
                "http://example.com:8899/storage/",
                "/genesis.tar.gz",
                "http://example.com:8899/storage/genesis.tar.gz",
            ),
            // HTTPS protocol
            (
                "https://example.com/storage",
                "genesis.tar.gz",
                "https://example.com/storage/genesis.tar.gz",
            ),
            // Nested paths
            (
                "http://example.com:8899/data/storage",
                "snapshots/genesis.tar.gz",
                "http://example.com:8899/data/storage/snapshots/genesis.tar.gz",
            ),
        ];

        for (base_url, path, expected) in test_cases {
            let base_uri = base_url.parse::<Uri>().unwrap();
            let result = MetadataScraper::join_urls(&base_uri, path).unwrap();
            assert_eq!(
                result, expected,
                "Failed for base '{base_url}' and path '{path}'"
            );
        }
    }
}

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, error, info};
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::RwLock;
use url::{ParseError, Url};

use crate::constants::DEFAULT_SNAPSHOT_INFO_PATH;

const CACHE_DURATION: Duration = Duration::from_secs(5);

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

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub shred_version: u16,
    pub genesis_hash: String,
}

#[derive(Debug, Clone)]
pub struct AtomicNetworkInfo {
    pub shred_version: Arc<AtomicU16>,
    pub genesis_hash: Arc<String>,
}

impl AtomicNetworkInfo {
    pub fn new(shred_version: u16, genesis_hash: String) -> Self {
        Self {
            shred_version: Arc::new(AtomicU16::new(shred_version)),
            genesis_hash: Arc::new(genesis_hash),
        }
    }

    pub fn get(&self) -> NetworkInfo {
        NetworkInfo {
            shred_version: self.shred_version.load(Ordering::SeqCst),
            genesis_hash: (*self.genesis_hash).clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SnapshotInfo {
    pub genesis_hash: String,
    pub shred_version: u16,
    pub slot: i64,
    pub full: Option<String>,
    pub incremental: Option<String>,
}

#[derive(Debug, PartialEq)]
enum SnapshotType {
    Genesis,
    Full,
    Incremental,
}

impl SnapshotType {
    fn from_path(path: &str) -> Result<Self, ScraperError> {
        if path.starts_with("/genesis") {
            Ok(Self::Genesis)
        } else if path.starts_with("/snapshot") {
            Ok(Self::Full)
        } else if path.starts_with("/incremental-snapshot") {
            Ok(Self::Incremental)
        } else {
            Err(ScraperError::ParseError(format!(
                "Unknown snapshot path: {}",
                path
            )))
        }
    }
}

pub struct MetadataScraper {
    storage_path: Option<Url>, // If not here, we'll always return the default snapshot info
    http_client: Client,
    expected_network_info: AtomicNetworkInfo,
    cache: RwLock<(SnapshotInfo, Instant)>,
}

impl MetadataScraper {
    pub fn storage_path(&self) -> Option<&Url> {
        self.storage_path.as_ref()
    }
    pub fn new(storage_path: Option<Url>, expected_network_info: AtomicNetworkInfo) -> Self {
        // use expected info as the defaults
        let genesis_hash = expected_network_info.genesis_hash.to_string();
        let shred_version = expected_network_info.shred_version.load(Ordering::SeqCst);
        Self {
            http_client: Client::new(),
            storage_path,
            expected_network_info,
            cache: RwLock::new((
                SnapshotInfo {
                    genesis_hash,
                    shred_version,
                    slot: 0,
                    full: None,
                    incremental: None,
                },
                Instant::now() - CACHE_DURATION * 2,
            )),
        }
    }

    async fn fetch_snapshot_info(&self) -> Result<SnapshotInfo, ScraperError> {
        if self.storage_path.is_none() {
            return Err(ScraperError::NetworkError(
                "Storage path is not configured".to_string(),
            ));
        }
        let url = format!(
            "{}/{}",
            self.storage_path.as_ref().unwrap(),
            DEFAULT_SNAPSHOT_INFO_PATH
        );
        let response = self.http_client.get(&url).send().await.map_err(|e| {
            ScraperError::NetworkError(format!("Failed to fetch snapshot info {}: {}", url, e))
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

        let expected = self.expected_network_info.get();

        if info.genesis_hash != expected.genesis_hash {
            return Err(ScraperError::NetworkMismatch(format!(
                "Genesis hash mismatch: got {}, expected {}",
                info.genesis_hash, expected.genesis_hash
            )));
        }

        if info.shred_version != expected.shred_version {
            return Err(ScraperError::NetworkMismatch(format!(
                "Shred version mismatch: got {}, expected {}",
                info.shred_version, expected.shred_version
            )));
        }

        Ok(info)
    }

    pub async fn get_cached_snapshot_info(&self) -> SnapshotInfo {
        let cache = self.cache.read().await;
        if cache.1.elapsed() < Duration::from_secs(5) {
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
                error!(
                    "Failed to fetch snapshot info, using stale info {:?}: {}",
                    info, e
                );
                info
            }
        }
    }

    async fn get_snapshot_path(&self, request_path: &str, snapshot_type: SnapshotType) -> String {
        let info = self.get_cached_snapshot_info().await;
        let path = match snapshot_type {
            SnapshotType::Full => &info.full,
            SnapshotType::Incremental => &info.incremental,
            SnapshotType::Genesis => &None,
        };
        path.clone().unwrap_or_else(|| request_path.to_string())
    }

    pub async fn build_url(&self, request_path: &str) -> Result<Url, ParseError> {
        let storage_url = self.storage_path.as_ref().ok_or(ParseError::EmptyHost)?;
        debug!("Building URL {} {}", storage_url, request_path);

        let real_path = self
            .get_snapshot_path(request_path, SnapshotType::from_path(request_path).unwrap())
            .await;
        let mut storage_url = storage_url.clone();
        debug!(
            "Building URL with storage_url {} and request {} -> {}",
            storage_url, request_path, real_path
        );
        {
            // Add on the real path to the stoarge url, which may already have a path
            let mut segments = storage_url
                .path_segments_mut()
                .map_err(|_| ParseError::SetHostOnCannotBeABaseUrl)?;
            segments.push(&real_path.trim_start_matches('/'));
        }
        debug!("Built {} into {}", real_path, storage_url);
        Ok(storage_url)
    }
}

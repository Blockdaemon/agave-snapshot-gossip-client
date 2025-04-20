use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, RwLock};

/// Holds shared atomic state accessible across different asynchronous tasks.
///
/// Provides thread-safe access to commonly needed runtime values like
/// peer counts, shred versions, and the node's public key.
#[derive(Clone)]
pub struct AtomicState {
    /// Number of connected gossip peers.
    num_peers: Arc<AtomicI64>,
    /// Currently observed shred version from gossip.
    shred_version: Arc<AtomicU16>,
    /// The public key of this node's identity keypair.
    public_key: Arc<RwLock<String>>,
}

impl AtomicState {
    /// Creates a new `AtomicState` instance with default values.
    ///
    /// - `num_peers` and `shred_version` start at 0.
    /// - `public_key` starts as an empty string.
    pub fn new() -> Self {
        Self {
            num_peers: Arc::new(AtomicI64::new(0)),
            shred_version: Arc::new(AtomicU16::new(0)),
            public_key: Arc::new(RwLock::new(String::new())),
        }
    }

    /// Sets the node's public key.
    pub fn set_public_key(&self, public_key: String) {
        *self.public_key.write().unwrap() = public_key;
    }

    /// Gets the node's public key.
    pub fn get_public_key(&self) -> String {
        self.public_key.read().unwrap().clone()
    }

    /// Gets the current number of gossip peers.
    ///
    /// Uses `Ordering::Relaxed` as only the latest available value is needed.
    pub fn get_num_peers(&self) -> i64 {
        self.num_peers.load(Ordering::Relaxed)
    }

    /// Sets the current number of gossip peers.
    ///
    /// Uses `Ordering::SeqCst` to ensure the write is globally ordered.
    pub fn set_num_peers(&self, value: i64) {
        self.num_peers.store(value, Ordering::SeqCst);
    }

    /// Gets the current shred version observed from gossip.
    ///
    /// Uses `Ordering::Relaxed` as only the latest available value is needed.
    pub fn get_shred_version(&self) -> u16 {
        self.shred_version.load(Ordering::Relaxed)
    }

    /// Sets the current shred version.
    ///
    /// Uses `Ordering::SeqCst` to ensure the write is globally ordered.
    pub fn set_shred_version(&self, value: u16) {
        self.shred_version.store(value, Ordering::SeqCst);
    }
}

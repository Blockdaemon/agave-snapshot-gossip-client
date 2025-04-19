use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct AtomicState {
    num_peers: Arc<AtomicI64>,
    shred_version: Arc<AtomicU16>,
    pub pubkey: Arc<RwLock<String>>,
}

impl AtomicState {
    pub fn new() -> Self {
        Self {
            num_peers: Arc::new(AtomicI64::new(0)),
            shred_version: Arc::new(AtomicU16::new(0)),
            pubkey: Arc::new(RwLock::new(String::new())),
        }
    }

    pub fn set_pubkey(&self, pubkey: String) {
        *self.pubkey.write().unwrap() = pubkey;
    }

    pub fn get_pubkey(&self) -> String {
        self.pubkey.read().unwrap().clone()
    }

    pub fn get_num_peers(&self) -> i64 {
        self.num_peers.load(Ordering::Relaxed)
    }

    pub fn set_num_peers(&self, value: i64) {
        self.num_peers.store(value, Ordering::SeqCst);
    }

    pub fn get_shred_version(&self) -> u16 {
        self.shred_version.load(Ordering::Relaxed)
    }

    pub fn set_shred_version(&self, value: u16) {
        self.shred_version.store(value, Ordering::SeqCst);
    }
}

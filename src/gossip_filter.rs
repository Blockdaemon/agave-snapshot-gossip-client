use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use solana_gossip::protocol::{FilterableCrdsDataType, FilterableProtocolType};

// --- Filter Modes ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipFilterMode {
    /// Minimal mode: Stays connected, publishes own state, minimal peer discovery.
    LightClient,
    /// Standard entry point: Serves pull requests, maintains basic cluster health view.
    Entrypoint,
    /// Listens for cluster state (excluding votes), stays connected. Does not serve pull requests.
    NonVotingRpc,
}

// --- Metrics Definitions ---

#[derive(Debug, Default)]
pub struct CrdsMetrics {
    pub total_messages_count: Arc<AtomicU64>,
    pub contact_info_count: Arc<AtomicU64>,
    pub vote_count: Arc<AtomicU64>,
    pub lowest_slot_count: Arc<AtomicU64>,
    pub snapshot_hashes_count: Arc<AtomicU64>,
    pub epoch_slots_count: Arc<AtomicU64>,
    pub duplicate_shred_count: Arc<AtomicU64>,
    pub restart_last_voted_fork_slots_count: Arc<AtomicU64>,
    pub restart_heaviest_fork_count: Arc<AtomicU64>,
    pub other_count: Arc<AtomicU64>, // Covers Version, NodeInstance, Other
}

#[derive(Debug, Default)]
pub struct ProtocolGossipMetrics {
    pub pull_request_count: Arc<AtomicU64>,
    pub prune_message_count: Arc<AtomicU64>,
    pub ping_count: Arc<AtomicU64>,
    pub pong_count: Arc<AtomicU64>,
    pub ingress_filter_calls_count: Arc<AtomicU64>,
    pub ingress_filtered_count: Arc<AtomicU64>,
    pub pull_response_metrics: CrdsMetrics,
    pub push_message_metrics: CrdsMetrics,
}

// --- Counting Logic ---

/// Increments metrics counters based on the incoming message type and data.
/// This function should be called *before* any filtering decision.
pub fn count_protocol_message(
    protocol_metrics: &ProtocolGossipMetrics,
    protocol_type: FilterableProtocolType,
    data_types: Option<&[FilterableCrdsDataType]>,
) {
    protocol_metrics
        .ingress_filter_calls_count
        .fetch_add(1, Ordering::Relaxed);

    match protocol_type {
        FilterableProtocolType::PullRequest => {
            protocol_metrics
                .pull_request_count
                .fetch_add(1, Ordering::Relaxed);
        }
        FilterableProtocolType::PullResponse => {
            let metrics_to_update = &protocol_metrics.pull_response_metrics;
            metrics_to_update
                .total_messages_count
                .fetch_add(1, Ordering::Relaxed);
            if let Some(data) = data_types {
                count_crds_data(metrics_to_update, data);
            }
        }
        FilterableProtocolType::PushMessage => {
            let metrics_to_update = &protocol_metrics.push_message_metrics;
            metrics_to_update
                .total_messages_count
                .fetch_add(1, Ordering::Relaxed);
            if let Some(data) = data_types {
                count_crds_data(metrics_to_update, data);
            }
        }
        FilterableProtocolType::PruneMessage => {
            protocol_metrics
                .prune_message_count
                .fetch_add(1, Ordering::Relaxed);
        }
        FilterableProtocolType::PingMessage => {
            protocol_metrics.ping_count.fetch_add(1, Ordering::Relaxed);
        }
        FilterableProtocolType::PongMessage => {
            protocol_metrics.pong_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Helper to count the different types within a CRDS data slice.
fn count_crds_data(metrics: &CrdsMetrics, data: &[FilterableCrdsDataType]) {
    for data_type in data {
        match data_type {
            FilterableCrdsDataType::ContactInfo => {
                metrics.contact_info_count.fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::Vote => {
                metrics.vote_count.fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::LowestSlot => {
                metrics.lowest_slot_count.fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::SnapshotHashes => {
                metrics
                    .snapshot_hashes_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::EpochSlots => {
                metrics.epoch_slots_count.fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::DuplicateShred => {
                metrics
                    .duplicate_shred_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::RestartLastVotedForkSlots => {
                metrics
                    .restart_last_voted_fork_slots_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            FilterableCrdsDataType::RestartHeaviestFork => {
                metrics
                    .restart_heaviest_fork_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                // Covers Version, NodeInstance, Other
                metrics.other_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// --- Filtering Logic ---

/// Determines if a message should be kept based on the selected filter mode.
pub fn filter_protocol_message(
    mode: GossipFilterMode,
    protocol_type: FilterableProtocolType,
    data_types: Option<&[FilterableCrdsDataType]>,
) -> bool {
    match protocol_type {
        // Always keep Ping/Pong for basic connectivity in all modes
        FilterableProtocolType::PingMessage | FilterableProtocolType::PongMessage => true,

        // Keep PullRequest only in Entrypoint mode
        FilterableProtocolType::PullRequest => matches!(mode, GossipFilterMode::Entrypoint),

        // Decide on PullResponse/PushMessage based on content and mode
        FilterableProtocolType::PullResponse | FilterableProtocolType::PushMessage => {
            should_keep_data_message(mode, data_types)
        }

        // Never discard PruneMessage in all defined modes
        FilterableProtocolType::PruneMessage => true,
    }
}

/// Helper to decide if a PullResponse or PushMessage should be kept based on its CRDS content.
fn should_keep_data_message(
    mode: GossipFilterMode,
    data_types: Option<&[FilterableCrdsDataType]>,
) -> bool {
    let Some(data) = data_types else {
        // Keep messages even if data_types is None or empty?
        // Such messages likely don't exist or are harmless.
        return true;
    };

    match mode {
        GossipFilterMode::LightClient => {
            // Keep *only* if it contains ContactInfo for peer discovery
            data.iter()
                .any(|dt| matches!(dt, FilterableCrdsDataType::ContactInfo))
        }
        GossipFilterMode::Entrypoint => {
            // Keep if *any* data type is essential for entry point health
            // (ContactInfo for topology, Vote/LowestSlot for basic health)
            data.iter().any(|dt| {
                matches!(
                    dt,
                    FilterableCrdsDataType::ContactInfo
                        | FilterableCrdsDataType::Vote
                        | FilterableCrdsDataType::LowestSlot
                )
            })
        }
        GossipFilterMode::NonVotingRpc => {
            // Keep if it contains ContactInfo or LowestSlot for basic state/topology
            data.iter().any(|dt| {
                matches!(
                    dt,
                    FilterableCrdsDataType::ContactInfo | FilterableCrdsDataType::LowestSlot
                )
            })
        }
    }
}

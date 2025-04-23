mod atomic_state;
mod config;
mod constants;
mod gossip;
mod gossip_filter;
mod healthcheck;
mod http_proxy;
mod ip_echo;
mod local_storage;
mod rpc;
mod scraper;
mod stun;
mod upnp;

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::Result;
use clap::Parser;
use env_logger;
use igd::PortMappingProtocol;
use log::{error, info, warn};

// Our local crates
use atomic_state::AtomicState;
use gossip::start_gossip_client;
use gossip_filter::ProtocolGossipMetrics;
use rpc::{start_rpc_service, AppState};
use scraper::MetadataScraper;
use solana_gossip::cluster_info::ClusterInfo;

#[derive(Parser)]
#[command(author, about, long_about = None, disable_version_flag = true)]
struct Cli {
    /// Print version information and exit
    #[arg(short, long)]
    version: bool,

    /// Path to config file
    #[arg(short, long, default_value = crate::constants::DEFAULT_CONFIG_PATH)]
    config: String,
}

async fn setup_signal_handler(exit: Arc<AtomicBool>) -> Result<(), tokio::task::JoinError> {
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| {
                error!("Failed to install SIGTERM handler: {}", e);
                std::process::exit(1);
            });
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .unwrap_or_else(|e| {
                error!("Failed to install SIGINT handler: {}", e);
                std::process::exit(1);
            });
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                warn!("Received CTRL+C");
            }
            _ = sigterm.recv() => {
                warn!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                warn!("Received SIGINT");
            }
        }
        exit.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.version {
        println!("agave-snapshot-gossip-client {}", env!("CARGO_PKG_VERSION"));
        println!("Build timestamp: {}", env!("BUILD_TIMESTAMP"));
        println!("Git tag: {}", env!("GIT_TAG"));
        println!("Git SHA: {}", env!("GIT_SHA"));
        return Ok(());
    }

    // Don't log timestamps under systemd
    let mut builder = env_logger::Builder::from_default_env();
    if std::env::var("INVOCATION_ID").is_ok() {
        // We're running under systemd
        builder.format_timestamp(None);
    } else {
        // Default format for non-systemd environments
        builder.format_timestamp_secs();
        builder.format_level(true);
        builder.format_target(true);
        builder.format_module_path(true);
    }

    // Set default log level to INFO if not specified
    if std::env::var("RUST_LOG").is_err() {
        // Default to turning off noisy dependencies and setting info level
        builder.parse_filters(constants::DEFAULT_LOG_FILTERS);
    }

    builder.init();

    info!("Starting up");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    let config = config::load_config(Some(&cli.config));
    let resolved = config.resolve().await.map_err(|e| {
        error!("Failed to resolve configuration: {:?}", e);
        e
    })?;

    info!("Public address: {}", resolved.public_ip);

    if resolved.entrypoints.is_empty() {
        return Err("No entrypoints configured".into());
    }

    // Try to set up UPnP port forwarding BEFORE signal handler
    if resolved.enable_upnp {
        if let Err(e) = upnp::setup_port_forwarding(
            vec![
                (resolved.gossip_port, PortMappingProtocol::UDP),
                (resolved.rpc_port, PortMappingProtocol::TCP),
            ],
            None,
        ) {
            error!("Failed to set up UPnP port forwarding: {}", e);
        }
    }

    // We make 3 exit clones, one for the signal handler, one for the gossip service, and one for the monitor
    let exit = Arc::new(AtomicBool::new(false));
    let exit_signal = exit.clone(); // Clone specifically for the final signal store

    info!("Setting up signal handler");
    let signal_handler = setup_signal_handler(exit.clone()); // Pass original exit clone

    // Create shared state (pubkey initialized empty, set by gossip client if enabled)
    let atomic_state = AtomicState::new();

    // Create scraper
    let scraper = Arc::new(MetadataScraper::new(
        resolved.storage_path.clone(),
        resolved.expected_genesis_hash.clone(),
    ));

    // Calculate serve_local based on scraper
    let serve_local = scraper
        .storage_path()
        .map(|uri| uri.scheme_str() == Some("file"))
        .unwrap_or(false);

    // Variable to hold ClusterInfo if gossip is enabled
    let mut cluster_info_instance: Option<Arc<ClusterInfo>> = None;
    // Initialize the unified metrics Arc directly
    let mut protocol_metrics = Arc::new(ProtocolGossipMetrics::default());

    // Initialize app state (using the default metrics initially)
    let mut app_state = AppState {
        scraper: scraper.clone(),
        atomic_state: atomic_state.clone(),
        disable_gossip: resolved.disable_gossip,
        enable_proxy: resolved.enable_proxy,
        serve_local,
        cluster_info: Arc::new(RwLock::new(None)),
        protocol_metrics: protocol_metrics.clone(), // Use the initialized metrics
    };

    // start gossip client if enabled
    let gossip_handles = if !resolved.disable_gossip {
        // Capture the 4 returned values, including the unified metrics
        let (monitor_handle, gossip_handle, cluster_info, pm) = start_gossip_client(
            &resolved,
            scraper.clone(),
            atomic_state.clone(),
            exit.clone(),
        )
        .await?;
        cluster_info_instance = Some(cluster_info);
        // Overwrite metrics with the ones from the gossip client
        protocol_metrics = pm;
        Some((monitor_handle, gossip_handle))
    } else {
        warn!("Gossip disabled, not starting gossip client");
        // Restore logic to set shred_version from config when gossip is off
        atomic_state.set_shred_version(resolved.shred_version.unwrap_or(0));
        None
    };

    // Update app state with cluster_info
    if let Some(cluster_info) = &cluster_info_instance {
        let mut cluster_info_lock = app_state.cluster_info.write().unwrap();
        *cluster_info_lock = Some(cluster_info.clone());
    }

    // Update AppState with the *final* metrics (either default or from gossip)
    app_state.protocol_metrics = protocol_metrics;

    // Start RPC service task
    let rpc_listen = SocketAddr::new(resolved.listen_ip, resolved.rpc_port);
    info!("Starting RPC server on {}...", rpc_listen);
    let rpc_handle = tokio::spawn(async move {
        // Pass AppState directly to the service function
        if let Err(e) = start_rpc_service(rpc_listen, app_state, exit.clone()).await {
            // Pass original exit clone
            error!("RPC server error: {}", e);
        }
    });
    info!("Started RPC server");

    warn!("Ready to accept connections");

    // Wait for signal or ctrl+c
    signal_handler.await.unwrap_or_else(|e| {
        error!("Failed to join signal handler: {}", e);
        std::process::exit(1);
    });

    // Clean up port forwarding if enabled
    if resolved.enable_upnp {
        if let Err(e) = upnp::cleanup_port_forwarding() {
            error!("Failed to cleanup UPnP port forwarding: {}", e);
        }
    }

    info!("Signaling RPC server to exit...");
    // Signal exit to gossip/monitor service and RPC server
    exit_signal.store(true, std::sync::atomic::Ordering::SeqCst); // Use the pre-cloned signal Arc

    info!("Waiting for RPC server shutdown...");
    rpc_handle.await.unwrap_or_else(|e| {
        error!("Failed to join RPC server task: {}", e);
        // Consider if process::exit is appropriate here or just log
    });
    info!("RPC server shutdown complete");

    // Wait for gossip services if they were started
    if let Some((monitor_handle, gossip_handle)) = gossip_handles {
        info!("Signaled gossip/monitor service to exit...");

        // Wait for monitor to complete
        monitor_handle.await.unwrap_or_else(|e| {
            error!("Failed to join monitor task: {}", e);
            std::process::exit(1);
        });
        info!("Gossip monitor shutdown complete");

        // Join gossip service
        info!("Waiting for gossip service shutdown...");
        gossip_handle.await.unwrap_or_else(|e| {
            error!("Failed to join gossip service: {}", e);
            std::process::exit(1);
        });
        info!("Gossip service shutdown complete");
    }

    warn!("Shutting down");
    std::process::exit(0);
}

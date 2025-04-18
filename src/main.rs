mod config;
mod constants;
mod gossip;
mod healthcheck;
mod http_proxy;
mod ip_echo;
mod rpc;
mod scraper;
mod stun;
mod upnp;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use env_logger;
use igd::PortMappingProtocol;
use log::{error, info, warn};

// Our local crates
use gossip::start_gossip_client;
use rpc::RpcServer;
use scraper::MetadataScraper;

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

    info!("Setting up signal handler");
    let signal_handler = setup_signal_handler(exit.clone()); // clone #1

    let num_peers = Arc::new(AtomicI64::new(0));
    let shred_version = Arc::new(AtomicU16::new(0));

    // Create scraper
    let scraper = Arc::new(MetadataScraper::new(
        resolved.storage_path.clone(),
        resolved.expected_genesis_hash.clone(),
    ));

    // start gossip client if enabled
    let gossip_handles = if !resolved.disable_gossip {
        let (monitor_handle, gossip_handle) = start_gossip_client(
            &resolved,
            scraper.clone(),
            exit.clone(),
            num_peers.clone(),
            shred_version.clone(),
        )
        .await?;
        Some((monitor_handle, gossip_handle))
    } else {
        shred_version.store(
            resolved
                .shred_version
                .unwrap_or(resolved.shred_version.unwrap_or(0)),
            std::sync::atomic::Ordering::SeqCst,
        );
        None
    };

    // Create rpc server
    let rpc_server = RpcServer::new(scraper, num_peers, shred_version, resolved.enable_proxy);

    let rpc_listen = SocketAddr::new(resolved.listen_ip, resolved.rpc_port);
    info!("Starting RPC server on {}...", rpc_listen);
    rpc_server.start(rpc_listen, exit.clone()).await?;
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
    exit.store(true, std::sync::atomic::Ordering::SeqCst);

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

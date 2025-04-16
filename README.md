# Solana Snapshot Delivery Network (SSDN) Gossip Client

## Overview

The SSDN Gossip Client is part of a solution to decouple snapshot serving from validator operations in the Solana network. It enables scalable snapshot distribution without impacting validator performance.

## Problem Statement

Current snapshot distribution has several limitations:
- Existing validators and RPC providers are overwhelmed with snapshot requests, and they are limited in number due to the added performance overhead
- Snapshot serving impacts critical validator operations
- Snapshot serving impacts critical RPC provider operations
- No scalability during high-demand periods (e.g., network restarts)
- No dedicated infrastructure for snapshot distribution

## Solution

This project, along with [agave-snapshot-uploader](https://github.com/Blockdaemon/agave-snapshot-uploader), provides a scalable snapshot delivery network by:
1. Decoupling snapshot distribution from validator/RPC operations
2. Reusing the existing discovery mechanism for snapshot sources
3. Maintaining compatibility with existing validator clients
4. Supporting flexible deployment options

### Key Features
- Gossip network integration for discovery
- Can be used as an entrypoint for the gossip network
- Minimum required JSONRPC endpoint compatibility for snapshot distribution (`getSlot`, `getVersion`, `getGenesisHash`)
- Additional non-standard JSONRPC methods (`getNumPeers`, `getShredVersion`)
- Native Agave support for `ip_echo` public IP and shred version discovery (client and server)
- Health endpoint on http://localhost:8899/health
- STUN support for public IP detection
- UPnP support for NAT traversal

## Architecture

The system supports three deployment models:

1. **Independent Gossip Client**
   - Separate gossip client (or RPC server only)
   - Uploader sidecar on validator

2. **Independent Client + Reverse Proxy**
   - Separate gossip client (or RPC server only)
   - Reverse proxy
   - Uploader sidecar on validator

3. **Simplified Legacy Setup - No Gossip Client**
   - No separate gossip client
   - All components on single host
   - Reverse proxy
   - Uploader sidecar

![Architecture Diagram](./docs/SSDN-Architecture.svg)

## Configuration

### Quick Start (if not using the Debian package)

1. Generate a keypair (if needed):
   ```bash
   solana-keygen new -o keypair.json
   ```

2. Create a `config.toml` file (optional, see [example-config.toml](example-config.toml))

- The only **required** setting is the `storage_path` to the snapshot location. Testnet is the default network.
- To use a different network, change `entrypoints` and `expected_genesis_hash` to the correct values for that network.

3. Run the client:
   ```bash
   RUST_LOG=warn cargo run -r
   ```
   or
   ```bash
   RUST_LOG=snapshot_gossip_client=info cargo run -r
   ```
   or
   ```bash
   RUST_LOG=solana_metrics=off,debug cargo run -r
   ```

See the [Installation Guide](INSTALL.md) file for more information on installing the Debian package or using docker.

### Configuration Options

Use `--config <path>` to specify a custom config file location. Default is `config.toml` in the current working directory.

| Option                   | Default                   | Description                 |
|--------------------------|---------------------------|-----------------------------|
| `entrypoints`            | Testnet                   | Gossip network entry points |
| `shred_version`          | None                      | Expected shred version      |
| `expected_genesis_hash`  | None                      | Expected genesis hash       |
| `keypair_path`           | `keypair.json`            | Path to keypair file        |
| `listen_ip`              | `0.0.0.0`                 | Local bind/listen IP        |
| `public_ip`              | Auto (STUN)               | Public IP address           |
| `enable_stun`            | `false`                   | Use STUN to discover public IP instead of `ip_echo` |
| `stun_server`            | `stun.l.google.com:3478`  | STUN server address         |
| `disable_gossip`         | `false`                   | Disable gossip client       |
| `gossip_port`            | `8001`                    | Gossip listen port          |
| `rpc_port`               | `8899`                    | RPC listen port             |
| `enable_upnp`            | `false`                   | Enable UPnP port forwarding |
| `storage_path`           | None                      | Redirect/proxy target URL   |
| `enable_proxy`           | `false`                   | Reverse proxy GET requests instead of redirecting |

`shred_version` is used when joining the gossip network. If you have issues
connecting to gossip, try setting it to the correct network value. If not
specified, the gossip client will attempt to autodetect it, but that is
unreliable.

`expected_genesis_hash` is used to verify the given `storage_path` is valid for
the network. If not specified, no checking will be done.

See [Solana Cluster Information](https://docs.anza.xyz/clusters/available) for the correct values.

### Network Requirements

- Static public IP address
- Ingress allow/forward list:
  - TCP/UDP port 8001 (gossip) - if you need to be a publicly reachable gossip entrypoint (optional)
  - TCP port 8899 (RPC) - A publicly reachable RPC endpoint is required for validators to accept snapshots from you

**Note**: STUN-based IP detection and UPnP port forwarding are not recommended for production.
Configure port firewall/forwarding rules manually. IP detection will be done via `ip_echo` to each entrypoint by default.

IP resolution preference order:
1. `public_ip` from user config (if provided)
2. IP echo result (if `public_ip` not provided)
3. STUN result (only if IP echo fails and STUN is enabled)

Shred version resolution:
1. If both configured and discovered versions exist and differ, it's an error
2. Use whichever version is available (either configured or discovered)
3. Return None if neither version is available

Note that even when `public_ip` is configured, IP echo is still attempted to get the shred version.

Explicit `public_ip` and `shred_version` configuration is always checked against `ip_echo` results.

## Known Issues
   - `--debug` builds may be unstable and have significantly higher memory and CPU usage. Use `-r` or `--release` to avoid this.
   - Large crate dependency footprint, huge memory and CPU usage for large gossip networks.
   - We do not periodically renew the UPnP port mappings, so if the router expires it, you may lose connectivity if you rely on on it ([issue #11](https://github.com/Blockdaemon/agave-snapshot-gossip-client/issues/11)).
   - For a detailed analysis of the benefits, limitations, and production considerations of the SSDN implementation, please see [TRADEOFFS.md](TRADEOFFS.md).

## License

[Apache 2.0](LICENSE)

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
- Bare minimum required RPC endpoint compatibility (`getSlot`, `getVersion`, `getGenesisHash`)
- STUN support for public IP detection
- UPnP support for NAT traversal

## Architecture

The system supports three deployment models:

1. **Independent Gossip Client**
   - Separate gossip client
   - Uploader sidecar on validator

2. **Independent Client + Reverse Proxy**
   - Separate gossip client
   - Reverse proxy
   - Uploader sidecar on validator

3. **Consolidated Setup**
   - All components on single host
   - Reverse proxy
   - Uploader sidecar

![Architecture Diagram](./docs/SSDN-Architecture.svg)

## Configuration

### Quick Start

1. Generate a keypair (if needed):
   ```bash
   solana-keygen new -o keypair.json
   ```

2. Create a `config.toml` file (optional, see [example-config.toml](example-config.toml))

3. Run the client:
   ```bash
   RUST_LOG=warn cargo run
   ```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `entrypoints` | Testnet | Gossip network entry points |
| `genesis_hash` | Testnet | Genesis hash |
| `keypair_path` | `keypair.json` | Path to keypair file |
| `rpc_listen` | `0.0.0.0:8899` | RPC listen address |
| `public_ip` | Auto (STUN), port `8001` | Public IP address |
| `stun_server` | `stun.l.google.com:3478` | STUN server address |
| `enable_upnp` | `false` | Enable UPnP port forwarding |
| `storage_server` | None | Storage server URL |

### Network Requirements

- For NAT/firewall setups:
  - UDP port 8001 (gossip)
  - TCP port 8899 (RPC)
  - Either:
    - Port forwarding configured for these ports
    - UPnP enabled on router (and `enable_upnp = true` locally)

**Note**: STUN-based IP detection and UPnP port forwarding are not recommended for production. Use explicit `public_ip` configuration instead, and configure port firewall/forwarding rules manually.

## Benefit/Limitation Tradeoffs

For a detailed analysis of the benefits, limitations, and production considerations of the SSDN implementation, please see [TRADEOFFS.md](TRADEOFFS.md).

## Known Issues
   - `getSlot` returns zero ([issue #5](https://github.com/Blockdaemon/agave-snapshot-gossip-client/issues/5))
   - Large dependency footprint from `solana_gossip`

## Contributing

Issues and pull requests are welcome. For major changes, please open an issue first to discuss the proposed changes.

## License

[Apache 2.0](LICENSE)

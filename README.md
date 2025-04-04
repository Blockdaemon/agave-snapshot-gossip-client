# Solana Snapshot Delivery Network (SSDN) Gossip Client

A lightweight client that participates in Solana's gossip network.

- The `public_ip` is reported to gossip, and is used as the P2P gossip listen point locally.
- Its keypair is used to report the public key that can be used as a `known_validator` for the purposes of providing snapshots.
- It listens on `rpc_listen` for `getSlot` `getVersion` and `getGenesisHash`.
- If a `storage_server` is supplied, it redirects all genesis/snapshot HTTP GET requests there.

![Alt text](./docs/SSDN-Architecture.svg)

## Configuration

Create a `config.toml` file. All settings are optional and will use default values if not specified, or there is no `config.toml` file.

See [example-config.toml](example-config.toml) for details.

If you are behind a NAT or firewall, this will only work if the gossip and RPC ports are forwarded to you. 
If they are not, you will need UPNP support on your NAT router and you'll have to `enable_upnp`.

### Default Values

- `entrypoints`: Solana Testnet
- `genesis_hash`: Solana Testnet
- `keypair_path`: `keypair.json`
- `rpc_listen`: `0.0.0.0:8899`
- `public_ip`: Autodetect with STUN
- `stun_server`: `stun.l.google.com:3478`
- `enable_upnp`: `false`
- `storage_server`: None

## Usage

1. Generate a keypair using `solana-keygen` if you do not have one already:
```bash
solana-keygen new -o keypair.json
```

2. Run the client:
```bash
RUST_LOG=warn cargo run
```

The client will:
- Load configuration from `config.toml` if present
- Use default values for any unspecified settings
- Auto-detect public addresses using STUN if not configured
- Generate a new keypair if none is found
- Find the lowest latency entry point in `entrypoints`
- Connect to the gossip cluster
- Listen on `rpc_listen` for JSONRPC requests and GET requests if `storage_server` is defined

## Bugs
- `getSlot` currently always returns zero. See
 [issue #5](https://github.com/Blockdaemon/agave-snapshot-gossip-client/issues/5)
 and
 [agave-snapshot-uploader issue #1](https://github.com/Blockdaemon/agave-snapshot-uploader/issues/1)
- If the single entrypoint selected from `entrypoints` is no good, no other entrypoints will be tried. See
[issue #2](https://github.com/Blockdaemon/agave-snapshot-gossip-client/issues/2)

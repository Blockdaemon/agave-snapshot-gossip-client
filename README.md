# Solana Snapshot Delivery Network (SSDN) Gossip Client

A lightweight client that participates in Solana's gossip network.

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
RUST_LOG=warn cargo run --bin snapshot-gossip-client
```

The client will:
- Load configuration from `config.toml` if present
- Use default values for any unspecified settings
- Auto-detect public addresses using STUN if not configured
- Generate a new keypair if none is found

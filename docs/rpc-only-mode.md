# Running in RPC-Only Mode (Gossip Disabled)

## Quick Start

**1. On the RPC-Only Node (`snapshot-gossip-client`):**
   * In `config.toml`:
 ```toml
     disable_gossip = true
     storage_path = "https://example.com/snapshots"
```

**2. On the advertisingr validator (assuming Agave):**
   * Use `--rpc-bind-address=http//<ip>:<port>` or
     the following environment variables:
```bash
   export RPC_PUBLIC_ENABLED=1
   export RPC_PUBLIC_IP=<IP of RPC-Only Node>
   export RPC_PUBLIC_PORT=<RPC Port of RPC-Only Node>
```

## Use Cases

To address concerns about non-voting nodes participating in gossip (see [#31](https://github.com/Blockdaemon/agave-snapshot-gossip-client/issues/31)), this mode runs `snapshot-gossip-client` solely as an HTTP server that handles snapshot requests without connecting to the gossip network. In this mode, consuming validators trust a conventional known validator's public key but fetch snapshots from a different HTTP endpoint than the actual validator. That known validator (the "Advertiser Validator" described below) will advertise an RPC endpoint which points to this snapshot server rather than its own.

This mode effectively turns the client into a dedicated snapshot cache, proxy, or redirector, depending on its configuration.

This mode is useful when:

*   Running on a non-voting node where gossip participation is undesirable or unnecessary.
*   Full gossip participation requires hardware and bandwith resources that are not available.

## Settings Details

*   **`storage_path`**: Defines where the client finds the snapshots and the `latest.json` manifest.
    *   For local files: `storage_path = "/path/to/your/snapshots"`
    *   For remote source: `storage_path = "http://remote.example.com/snapshots/"`

*   **`enable_proxy`** (Only if `storage_path` is HTTP/S):
    *   `enable_proxy = true`: The client will fetch snapshots from the `storage_path` URL and stream them to the requester.
    *   `enable_proxy = false`: The client will issue an HTTP 307 Temporary Redirect to the actual snapshot URL constructed from `storage_path`.

*   **Ignored Settings**: When `disable_gossip = true`, the following settings in `config.toml` are ignored:
    *   `entrypoints`
    *   `keypair_path`
    *   `public_ip`
    *   `gossip_port`
    *   `expected_genesis_hash` (snapshot validation is bypassed)
    *   `shred_version`

*   **Advertising Validator:**

    Since the `snapshot-gossip-client` is running with gossip disabled, it cannot announce itself to the network. Therefore, you must configure a *different* validator node (which *is* participating in gossip) to advertise the HTTP endpoint of the RPC-only client.

*  **Network Accessibility:**

    Ensure the RPC-Only Node's HTTP endpoint (the configured `listen_ip` and `rpc_port`) is network-reachable from the validators that will download snapshots from it. Check firewalls if necessary.

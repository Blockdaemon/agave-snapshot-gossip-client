# Installation Guilde
## Debian Package Installation

The Agave Snapshot Gossip Client is available as a Debian package, and runs as a systemd service.

Download the package from the [Release Page](https://github.com/Blockdaemon/agave-snapshot-gossip-client/releases) or wget it:

```bash
wget https://github.com/Blockdaemon/agave-snapshot-gossip-client/releases/download/v#.#.#/agave-snapshot-gossip-client_#.#.#_amd64.deb
```

Install the package:
```bash
sudo dpkg -i agave-snapshot-gossip-client_#####_amd64.deb
```

Edit the config file - you must configure `storage_path` and comment out `disable_gossip` when ready to join the network! By default, `storage_path` is `/var/www`, which is local storage.
```bash
sudo nano /etc/gossip-client/config.toml
```

Restart the service:
```bash
sudo systemctl restart gossip-client
```

Check the status and logs:
```bash
sudo systemctl status gossip-client
sudo journalctl -u gossip-client -f
```

## Docker

The application is available as a Docker image from GitHub Container Registry.

### Pulling the Image

For the latest stable release:
```bash
docker pull ghcr.io/blockdaemon/agave-snapshot-gossip-client:latest
```

For a specific version:
```bash
docker pull ghcr.io/blockdaemon/agave-snapshot-gossip-client:v1.0.0
```

For testing a pull request:
```bash
docker pull ghcr.io/blockdaemon/agave-snapshot-gossip-client:pr-123
```

### Running the Container

1. Create a config file (see `example-config.toml`)
2. Run the container with your config:
```bash
docker run -v /path/to/config.toml:/etc/snapshot-gossip-client/config.toml ghcr.io/blockdaemon/agave-snapshot-gossip-client:latest
```

The container exposes the following ports:
- 8001/udp - Gossip protocol
- 8001/tcp - Gossip protocol
- 8899/tcp - RPC server

Make sure to map these ports when running the container if you need to access them from outside:
```bash
docker run -p 8001:8001/udp -p 8001:8001/tcp -p 8899:8899/tcp -v /path/to/config.toml:/etc/snapshot-gossip-client/config.toml ghcr.io/blockdaemon/agave-snapshot-gossip-client:latest
```

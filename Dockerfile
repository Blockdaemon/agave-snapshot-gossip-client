# Final stage
FROM debian:bookworm-slim

# Default binary path for local builds
ARG BINARY_PATH=target/x86_64-unknown-linux-gnu/release/snapshot-gossip-client

# Install only runtime dependencies and clean up in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libudev1 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user and directories in one layer
RUN useradd -m -s /bin/bash snapshot-gossip-client && \
    mkdir -p /etc/snapshot-gossip-client /var/lib/snapshot-gossip-client && \
    chown -R snapshot-gossip-client:snapshot-gossip-client /etc/snapshot-gossip-client /var/lib/snapshot-gossip-client

# Copy the binary and docs
COPY --chown=snapshot-gossip-client:snapshot-gossip-client ${BINARY_PATH} /usr/local/sbin/snapshot-gossip-client
COPY --chown=snapshot-gossip-client:snapshot-gossip-client README.md /usr/local/share/doc/snapshot-gossip-client/README.md

# Set up the working directory
WORKDIR /var/lib/snapshot-gossip-client

# Expose ports (documentation only)
EXPOSE 8001/udp 8001/tcp 8899/tcp

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8899/health || exit 1

# Switch to the non-root user
USER snapshot-gossip-client

# Set the entrypoint
ENV RUST_LOG=solana_metrics::metrics=off,solana_gossip::cluster_info=off,info
ENTRYPOINT ["/usr/local/sbin/snapshot-gossip-client", "-c", "/etc/snapshot-gossip-client/config.toml"]

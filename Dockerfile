# Final stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libudev1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from either local build or CI artifacts
ARG BINARY_PATH=target/release/snapshot-gossip-client
COPY ${BINARY_PATH} /usr/local/sbin/snapshot-gossip-client
COPY README.md /usr/local/share/doc/snapshot-gossip-client/README.md

# Create a non-root user
RUN useradd -m -s /bin/bash snapshot-gossip-client

# Create config directory
RUN mkdir -p /etc/snapshot-gossip-client && \
    chown -R snapshot-gossip-client:snapshot-gossip-client /etc/snapshot-gossip-client

# Set up the working directory and permissions
WORKDIR /var/lib/snapshot-gossip-client
RUN chown -R snapshot-gossip-client:snapshot-gossip-client /var/lib/snapshot-gossip-client

# Expose ports (documentation only, actual ports should be mapped at runtime)
EXPOSE 8001/udp 8001/tcp 8899/tcp

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8899/health || exit 1

# Switch to the non-root user
USER snapshot-gossip-client

# Set the entrypoint
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/sbin/snapshot-gossip-client", "-c", "/etc/snapshot-gossip-client/config.toml"]

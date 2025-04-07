#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

VERSION=$1
TAG="v${VERSION}"

# Update Cargo.toml version
sed -i '' "s/^version = .*/version = \"${VERSION}\"/" Cargo.toml

# Commit the version update
git add Cargo.toml
git commit -m "Bump version to ${VERSION}"

# Create and push the tag
git tag -a "${TAG}" -m "Release ${TAG}"
git push origin main
git push origin "${TAG}"

# Build and verify version
echo "Building and verifying version..."
cargo build --release
./target/release/agave-snapshot-gossip-client --version

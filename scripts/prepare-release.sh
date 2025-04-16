#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 $(git describe --tags --abbrev=0 | sed 's/v//' | awk -F. '{print $1"."$2"."$3+1}')"
    exit 1
fi

VERSION=$1
TAG="v${VERSION}"
TIMESTAMP=$(date -R)

# Update Cargo.toml version
sed -i '' "s/^version = .*/version = \"${VERSION}\"/" Cargo.toml

# Build and verify version
echo "Building and verifying version..."
cargo fmt
# do this a few times to ensure all dependencies are up to date
cargo update
cargo update
cargo build --release
./target/release/snapshot-gossip-client --version

# Update Debian changelog
dch --newversion "${VERSION}" --distribution unstable "Release ${TAG}"
dch --release ""
# Fix the timestamp in the changelog (only the last line)
sed -i '' "$ s/^ -- .*/ -- Blockdaemon <support@blockdaemon.com>  ${TIMESTAMP}/" debian/changelog

# Commit the version updates
git add Cargo.toml Cargo.lock debian/changelog
git commit -m "Bump version to ${VERSION}" || true

# Create and push the tag
git tag -d "${TAG}" || true
git tag -a "${TAG}" -m "Release ${TAG}"
echo You still need to "git push origin main && git push origin ${TAG}"

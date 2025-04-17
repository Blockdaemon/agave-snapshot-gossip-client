#!/bin/bash

# Set the repository name
REPO="blockdaemon/agave-snapshot-gossip-client"

# Create temp directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Ensure target directory exists
mkdir -p target/x86_64-unknown-linux-gnu/release/

# Check for GitHub token
if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN environment variable is not set"
    echo "Please set your GitHub token: export GITHUB_TOKEN=your_token"
    exit 1
fi

echo "Fetching latest build..."

# Get the latest successful workflow run
RUN_URL="https://api.github.com/repos/$REPO/actions/runs?per_page=5&status=completed&workflow=debian.yml"
RUN_INFO=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "$RUN_URL")

# Find the first successful run
RUN_ID=""
for i in $(seq 0 4); do
    RUN=$(echo "$RUN_INFO" | jq -r ".workflow_runs[$i]")
    if [ "$RUN" = "null" ]; then
        break
    fi
    CONCLUSION=$(echo "$RUN" | jq -r '.conclusion')
    RUN_ID=$(echo "$RUN" | jq -r '.id')
    if [ "$CONCLUSION" = "success" ]; then
        break
    fi
    RUN_ID=""
done

if [ -z "$RUN_ID" ]; then
    echo "Failed to find a successful workflow run"
    exit 1
fi

echo "Found workflow run ID: $RUN_ID"

# Get workflow run details including jobs
echo "Getting workflow run details..."
RUN_DETAILS_URL="https://api.github.com/repos/$REPO/actions/runs/$RUN_ID"
RUN_DETAILS=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "$RUN_DETAILS_URL")

# Get the runner environment
RUNNER=$(echo "$RUN_DETAILS" | jq -r '.runner_name')

# Get the artifact
echo "Getting artifact..."
ARTIFACT_URL="https://api.github.com/repos/$REPO/actions/runs/$RUN_ID/artifacts"
ARTIFACT_RESPONSE=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "$ARTIFACT_URL")
ARTIFACT_ID=$(echo "$ARTIFACT_RESPONSE" | jq -r '.artifacts[] | select(.name=="linux-x86_64") | .id')

if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" == "null" ]; then
    echo "Failed to get artifact ID from $ARTIFACT_URL"
    exit 1
fi

echo "Downloading binary..."
curl -s -L -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/actions/artifacts/$ARTIFACT_ID/zip" -o "$TMPDIR/artifact.zip"
unzip -q -o -j "$TMPDIR/artifact.zip" "snapshot-gossip-client" -d target/x86_64-unknown-linux-gnu/release/
rm "$TMPDIR/artifact.zip"

# Check glibc version
GLIBC_VERSION=$(objdump -T target/x86_64-unknown-linux-gnu/release/snapshot-gossip-client | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -n1 | sed 's/GLIBC_//')

# Check Dockerfile compatibility
DOCKERFILE_BASE=$(grep '^FROM' Dockerfile | awk '{print $2}')
echo "Dockerfile: $DOCKERFILE_BASE"
# Get the glibc version of the current base image
case "$DOCKERFILE_BASE" in
    "debian:bullseye-slim") CURRENT_GLIBC="2.31" ;;
    "debian:bookworm-slim") CURRENT_GLIBC="2.36" ;;
    "debian:unstable-slim") CURRENT_GLIBC="2.38" ;;
    "ubuntu:20.04") CURRENT_GLIBC="2.31" ;;
    "ubuntu:22.04") CURRENT_GLIBC="2.35" ;;
    "ubuntu:23.04") CURRENT_GLIBC="2.37" ;;
    "ubuntu:23.10") CURRENT_GLIBC="2.38" ;;
    *) CURRENT_GLIBC="" ;;
esac

echo "Binary glibc: $GLIBC_VERSION"
if [ -z "$CURRENT_GLIBC" ]; then
    echo "ERROR: Unknown base image $DOCKERFILE_BASE, cannot determine glibc version"
    rm -f target/x86_64-unknown-linux-gnu/release/snapshot-gossip-client
    exit 1
fi
echo "Docker glibc: $CURRENT_GLIBC"

if [ "$(printf '%s\n' "$GLIBC_VERSION" "$CURRENT_GLIBC" | sort -V | tail -n1)" != "$CURRENT_GLIBC" ]; then
    echo "Consider updating the build environment in .github/workflows/debian.yml to match the target glibc version"
    echo "ERROR: Base image glibc version ($CURRENT_GLIBC) is older than required ($GLIBC_VERSION)!"
    rm -f target/x86_64-unknown-linux-gnu/release/snapshot-gossip-client
    exit 1
fi

echo "Success! Binary downloaded to target/x86_64-unknown-linux-gnu/release/snapshot-gossip-client"

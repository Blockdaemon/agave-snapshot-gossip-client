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

# Try build workflow first, then release workflow
for workflow in "build" "release"; do
    echo "Checking $workflow workflow..."

    # Get the latest successful workflow run
    RUN_ID=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/$REPO/actions/workflows/$workflow.yml/runs?status=success&per_page=1" | \
      jq -r '.workflow_runs[0].id')

    if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
        echo "No successful runs found for $workflow workflow"
        continue
    fi

    echo "Found workflow run ID: $RUN_ID"

    # Check if the run has artifacts
    echo "Checking for artifacts..."
    ARTIFACT_URL="https://api.github.com/repos/$REPO/actions/runs/$RUN_ID/artifacts"
    ARTIFACT_RESPONSE=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "$ARTIFACT_URL")
    ARTIFACT_COUNT=$(echo "$ARTIFACT_RESPONSE" | jq -r '.total_count')

    if [ "$ARTIFACT_COUNT" -eq 0 ]; then
        echo "No artifacts found in run $RUN_ID"
        continue
    fi

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

    if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
        echo "Found artifact ID: $ARTIFACT_ID"
        # Get the workflow run timestamp
        RUN_TIMESTAMP=$(echo "$RUN_DETAILS" | jq -r '.created_at')
        # Use Python for reliable timestamp comparison, MacOS date command can't handle timezone conversions
        HOURS_ELAPSED=$(python3 -c "from datetime import datetime, timezone; import sys; \
            run_time = datetime.strptime(sys.argv[1], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc); \
            now = datetime.now(timezone.utc); \
            print(int((now - run_time).total_seconds() / 3600))" "$RUN_TIMESTAMP")
        echo "$RUN_TIMESTAMP is $HOURS_ELAPSED hours ago"
        # Successfully found an artifact
        break
    fi
    echo "Failed to get artifact ID from $ARTIFACT_URL"
done

if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" == "null" ]; then
    echo "Error: No artifacts found in either workflow"
    exit 1
fi

echo "Downloading binary..."
curl -s -L -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/actions/artifacts/$ARTIFACT_ID/zip" -o "$TMPDIR/artifact.zip"
unzip -q -o -j "$TMPDIR/artifact.zip" "snapshot-gossip-client" -d target/x86_64-unknown-linux-gnu/release/
rm "$TMPDIR/artifact.zip"

# Check if we found and downloaded an artifact
if [ ! -f "target/x86_64-unknown-linux-gnu/release/snapshot-gossip-client" ]; then
    echo "Error: No successful builds with artifacts found in either workflow"
    exit 1
fi

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

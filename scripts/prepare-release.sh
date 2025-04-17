#!/bin/bash
set -e

VERSION=$(git describe --tags --abbrev=0 | sed 's/v//' | awk -F. '{print $1"."$2"."$3+1}')
if [ -z "$1" ]; then
    echo "Usage: $0 [--version=<version>] [--dry-run]"
    echo "Example: $0 --version=${VERSION}"
    echo "Options:"
    echo "  --version=<version>  Version to release (e.g. ${VERSION})"
    echo "  --dry-run           Show what would be done without making changes"
    exit 1
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

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
cargo check
cargo build
./target/debug/snapshot-gossip-client --version

# Function to update changelog
update_changelog() {
    # Add a new changelog section at the top
    local changelog_entry="agave-snapshot-gossip-client (${VERSION}) unstable; urgency=medium

  * Release ${VERSION}

 -- Blockdaemon <support@blockdaemon.com>  ${TIMESTAMP}
"
    # Insert the new entry at the top of the file
    echo -e "${changelog_entry}$(cat debian/changelog)" > debian/changelog
}

# Update the changelog
update_changelog

# Function to run git commands with dry run support
run_git_cmd() {
    local cmd="$1"
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would run: $cmd"
    else
        eval "$cmd"
    fi
}

# Commit the version updates
run_git_cmd "git add Cargo.toml Cargo.lock debian/changelog"
run_git_cmd "git commit -m \"Bump version to ${VERSION}\" || true"
run_git_cmd "git tag -d \"${TAG}\" > /dev/null 2>&1 || true"
run_git_cmd "git tag -a \"${TAG}\" -m \"Release ${TAG}\""

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would need to run: git push origin main && git push origin ${TAG}"
else
    echo "You still need to \"git push origin main && git push origin ${TAG}\""
fi

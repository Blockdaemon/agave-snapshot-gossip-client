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

# Function to run git commands with dry run support
run_git_cmd() {
    local cmd="$1"
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would run: $cmd"
    else
        eval "$cmd"
    fi
}

# Get current branch
CURRENT_BRANCH=$(git symbolic-ref --short HEAD)
DEFAULT_BRANCH=$(git remote show origin | grep 'HEAD branch' | cut -d' ' -f5)

# Check if we're on the default branch
if [ "$DRY_RUN" != true -a "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ]; then
    echo "Error: Must be on the default branch ($DEFAULT_BRANCH) to prepare a release"
    exit 1
fi

# fetch the latest changes from origin
git fetch origin

# Force reset debian/changelog to origin
git checkout origin/$DEFAULT_BRANCH -- debian/changelog

TAG="v${VERSION}"
TIMESTAMP=$(date -R)

# Update Cargo.toml version
sed -i '' "s/^version = .*/version = \"${VERSION}\"/" Cargo.toml

# Build and verify version
echo "Building and verifying version..."
cargo fmt
cargo update
cargo check
cargo build
./target/debug/snapshot-gossip-client --version

# remove the tag if it already exists so we can get the changelog properly
run_git_cmd "git tag -d \"${TAG}\" > /dev/null 2>&1 || true"

# Function to update changelog
update_changelog() {
    # Get the last tag
    local last_tag=$(git describe --abbrev=0 --tags)

    # Get changes since last tag
    local changes=$(git log --reverse --pretty=format:"  * %s" ${last_tag}..HEAD)

    # Get committer info from git config
    local committer_name=$(git config user.name)
    local committer_email=$(git config user.email)

    # Check if this version already exists in changelog
    if grep -q "agave-snapshot-gossip-client (${VERSION})" debian/changelog; then
        echo "Warning: Version ${VERSION} already exists in changelog. Skipping changelog update."
        return
    fi

    # Add a new changelog section at the top
    local changelog_entry
    changelog_entry=$(cat <<EOF
agave-snapshot-gossip-client (${VERSION}) unstable; urgency=medium

${changes}

 -- ${committer_name} <${committer_email}>  ${TIMESTAMP}

EOF
    )

    # Insert the new entry at the top of the file
    echo -e "${changelog_entry}\n\n$(cat debian/changelog)" > debian/changelog
}

# Update the changelog
update_changelog

# Commit the version updates
run_git_cmd "git add Cargo.toml Cargo.lock debian/changelog"
run_git_cmd "git commit -m \"Bump version to ${VERSION}\" -S || true"
run_git_cmd "git tag -a \"${TAG}\" -m \"Release ${TAG}\""

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would need to run: git push origin main && git push origin ${TAG}"
else
    echo "You still need to \"git push origin main && git push origin ${TAG}\""
fi

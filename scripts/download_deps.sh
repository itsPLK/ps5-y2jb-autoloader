#!/usr/bin/env bash
# Script to download dependency binaries from GitHub releases

set -euo pipefail

# Ensure we are in the project root
cd "$(dirname "$0")/.."

DEST_DIR="src"
mkdir -p "$DEST_DIR"


echo "Checking for curl..."
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required to download dependencies." >&2
    exit 1
fi

CURL_CMD=(curl -s)
if [ -n "${GITHUB_TOKEN:-}" ]; then
    CURL_CMD+=(-H "Authorization: token $GITHUB_TOKEN")
elif [ -n "${GH_TOKEN:-}" ]; then
    CURL_CMD+=(-H "Authorization: token $GH_TOKEN")
fi

resolve_dep_release_url() {
    local submodule_dir="$1"
    local repo="$2"
    local ext_regex="$3"

    local tag=""
    if [ -e "$submodule_dir/.git" ]; then
        tag=$(git -C "$submodule_dir" tag --points-at HEAD 2>/dev/null | sort -V | tail -n 1 || true)
    fi

    local pinned_hash=""
    pinned_hash=$(git rev-parse ":$submodule_dir" 2>/dev/null | cut -c1-7 || git ls-tree HEAD "$submodule_dir" 2>/dev/null | awk '{print $3}' | cut -c1-7 || true)

    local url=""
    if [ -n "$tag" ]; then
        local release_json
        release_json=$("${CURL_CMD[@]}" "https://api.github.com/repos/$repo/releases/tags/$tag" || true)
        url=$(echo "$release_json" | grep -o "https://github.com/$repo/releases/download/[^\"]*$ext_regex" | head -n 1 || true)
    fi

    if [ -z "$url" ] && [ -n "$pinned_hash" ]; then
        local all_releases
        all_releases=$("${CURL_CMD[@]}" "https://api.github.com/repos/$repo/releases" || true)
        local matching_tag
        matching_tag=$(echo "$all_releases" | grep -o "\"tag_name\": \"[^\"]*$pinned_hash[^\"]*\"" | cut -d"\"" -f4 | sort -V | tail -n 1 || true)
        if [ -n "$matching_tag" ]; then
            url=$("${CURL_CMD[@]}" "https://api.github.com/repos/$repo/releases/tags/$matching_tag" | grep -o "https://github.com/$repo/releases/download/[^\"]*$ext_regex" | head -n 1 || true)
        fi
    fi

    if [ -z "$url" ]; then
        echo "Error: Could not retrieve release URL for $repo matching pinned submodule ($tag / $pinned_hash)." >&2
        exit 1
    fi

    echo "$url"
}

echo "Resolving release URL for pinned ps5-elfldr..."
ELFLDR_URL=$(resolve_dep_release_url "third_party/ps5-elfldr" "itsPLK/ps5-elfldr" '\.elf')

echo "Resolving release URL for pinned ps5-kexp..."
KEXP_URL=$(resolve_dep_release_url "third_party/ps5-kexp" "itsPLK/ps5-kexp" '\.bin')

echo "Resolving release URL for pinned ps5-unified-autoloader..."
AUTOLOADER_URL=$(resolve_dep_release_url "third_party/ps5-unified-autoloader" "itsPLK/ps5-unified-autoloader" '\.elf')

ELFLDR_VER=$(echo "$ELFLDR_URL" | grep -oE 'download/[^/]+' | cut -d'/' -f2)
KEXP_VER=$(echo "$KEXP_URL" | grep -oE 'download/[^/]+' | cut -d'/' -f2)
AUTOLOADER_VER=$(echo "$AUTOLOADER_URL" | grep -oE 'download/[^/]+' | cut -d'/' -f2)

if [ "${GITHUB_OUTPUT:-}" ]; then
    echo "elfldr_ver=${ELFLDR_VER}" >> "$GITHUB_OUTPUT"
    echo "kexp_ver=${KEXP_VER}" >> "$GITHUB_OUTPUT"
    echo "unified_autoloader_ver=${AUTOLOADER_VER}" >> "$GITHUB_OUTPUT"
fi

# Clean old dependency files
echo "Cleaning old binaries from $DEST_DIR..."
rm -f "$DEST_DIR"/kexp-*.bin
rm -f "$DEST_DIR"/elfldr-ps5-*.elf
rm -f "$DEST_DIR"/kexp_v*.bin
rm -f "$DEST_DIR"/elfldr*.elf
rm -f "$DEST_DIR"/ps5-unified-autoloader*.elf

ELFLDR_FILE="elfldr-ps5-${ELFLDR_VER}.elf"
KEXP_FILE="kexp-${KEXP_VER}.bin"
AUTOLOADER_FILE="ps5-unified-autoloader.elf"

# Download assets
echo "Downloading $ELFLDR_URL to $DEST_DIR/$ELFLDR_FILE..."
curl -L -o "$DEST_DIR/$ELFLDR_FILE" "$ELFLDR_URL"

echo "Downloading $KEXP_URL to $DEST_DIR/$KEXP_FILE..."
curl -L -o "$DEST_DIR/$KEXP_FILE" "$KEXP_URL"

echo "Downloading $AUTOLOADER_URL to $DEST_DIR/$AUTOLOADER_FILE..."
curl -L -o "$DEST_DIR/$AUTOLOADER_FILE" "$AUTOLOADER_URL"

echo "Successfully downloaded all dependencies!"
echo "Dependency versions:"
echo "  - elfldr: $ELFLDR_VER"
echo "  - kexp: $KEXP_VER"
echo "  - unified-autoloader: $AUTOLOADER_VER"
ls -la "$DEST_DIR"

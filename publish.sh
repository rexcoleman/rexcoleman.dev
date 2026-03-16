#!/usr/bin/env bash
set -euo pipefail

# publish.sh — Automate publishing a blog post from a project repo to the Hugo site
#
# Usage:
#   ./publish.sh <project-dir> <post-slug> [--draft]
#
# Example:
#   ./publish.sh ~/financial-anomaly-detection financial-fraud

SITE_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTENT_DIR="${SITE_DIR}/content/posts"
STATIC_DIR="${SITE_DIR}/static/images"

# --- Argument parsing -----------------------------------------------------------

DRAFT=false
PROJECT_DIR=""
POST_SLUG=""

for arg in "$@"; do
    case "$arg" in
        --draft) DRAFT=true ;;
        *)
            if [[ -z "$PROJECT_DIR" ]]; then
                PROJECT_DIR="$arg"
            elif [[ -z "$POST_SLUG" ]]; then
                POST_SLUG="$arg"
            else
                echo "Error: unexpected argument '$arg'"
                echo "Usage: $0 <project-dir> <post-slug> [--draft]"
                exit 1
            fi
            ;;
    esac
done

if [[ -z "$PROJECT_DIR" || -z "$POST_SLUG" ]]; then
    echo "Usage: $0 <project-dir> <post-slug> [--draft]"
    exit 1
fi

# Resolve project dir to absolute path
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

# --- Step 1: Verify source draft exists -----------------------------------------

DRAFT_FILE="${PROJECT_DIR}/blog/draft.md"
if [[ ! -f "$DRAFT_FILE" ]]; then
    echo "Error: ${DRAFT_FILE} does not exist."
    echo "Create your draft at <project-dir>/blog/draft.md first."
    exit 1
fi

echo "Source:  ${DRAFT_FILE}"
echo "Target:  ${CONTENT_DIR}/${POST_SLUG}.md"

# --- Step 2: Copy draft to content/posts/ --------------------------------------

DEST_FILE="${CONTENT_DIR}/${POST_SLUG}.md"
mkdir -p "$CONTENT_DIR"
cp "$DRAFT_FILE" "$DEST_FILE"

# --- Step 3: Add Hugo front matter if not present -------------------------------

has_front_matter() {
    head -1 "$1" | grep -q '^\-\-\-' && return 0 || return 1
}

if ! has_front_matter "$DEST_FILE"; then
    echo ""
    echo "No Hugo front matter detected. Let's add it."
    read -rp "Post title: " POST_TITLE

    # Extract candidate tags from content (words after # headers, code fences lang hints)
    CANDIDATE_TAGS=$(grep -oP '(?<=^## ).*|(?<=^### ).*' "$DEST_FILE" \
        | tr '[:upper:]' '[:lower:]' \
        | tr -cs '[:alnum:]\n' ' ' \
        | sort -u \
        | head -10 \
        | tr '\n' ', ' \
        | sed 's/, $//')

    echo "Suggested tags (from headings): ${CANDIDATE_TAGS:-none found}"
    read -rp "Tags (comma-separated): " USER_TAGS

    # Build tag list as YAML array
    TAG_YAML=""
    if [[ -n "$USER_TAGS" ]]; then
        IFS=',' read -ra TAG_ARR <<< "$USER_TAGS"
        for t in "${TAG_ARR[@]}"; do
            trimmed="$(echo "$t" | xargs)"
            TAG_YAML="${TAG_YAML}  - \"${trimmed}\"\n"
        done
    fi

    DRAFT_FLAG="false"
    if $DRAFT; then
        DRAFT_FLAG="true"
    fi

    TODAY="$(date +%Y-%m-%d)"

    FRONT_MATTER="---
title: \"${POST_TITLE}\"
date: ${TODAY}
draft: ${DRAFT_FLAG}
author: \"Rex Coleman\"
tags:
$(echo -e "$TAG_YAML")ShowToc: true
---
"

    # Prepend front matter
    TMPFILE="$(mktemp)"
    echo "$FRONT_MATTER" > "$TMPFILE"
    cat "$DEST_FILE" >> "$TMPFILE"
    mv "$TMPFILE" "$DEST_FILE"

    echo "Front matter added."
else
    echo "Front matter already present."
    # Step 6: If --draft flag, force draft: true in existing front matter
    if $DRAFT; then
        if grep -q '^draft:' "$DEST_FILE"; then
            sed -i 's/^draft:.*/draft: true/' "$DEST_FILE"
        else
            # Insert draft: true after the first ---
            sed -i '0,/^---$/!{/^---$/!{/^title:/a draft: true
}}' "$DEST_FILE"
        fi
        echo "Set draft: true"
    fi
fi

# --- Step 4: Copy images -------------------------------------------------------

IMG_SRC="${PROJECT_DIR}/blog/images"
IMG_DEST="${STATIC_DIR}/${POST_SLUG}"

if [[ -d "$IMG_SRC" ]] && [[ -n "$(ls -A "$IMG_SRC" 2>/dev/null)" ]]; then
    mkdir -p "$IMG_DEST"
    cp -r "${IMG_SRC}/"* "$IMG_DEST/"
    IMG_COUNT=$(find "$IMG_DEST" -type f | wc -l)
    echo "Copied ${IMG_COUNT} image(s) to ${IMG_DEST}/"
else
    echo "No images found at ${IMG_SRC}/ — skipping."
fi

# --- Step 5: Update image paths in markdown ------------------------------------

# Replace relative image paths with Hugo static paths
# Handles: ![alt](images/foo.png) and ![alt](./images/foo.png)
sed -i -E "s|\((\./)?images/|\(/images/${POST_SLUG}/|g" "$DEST_FILE"

# Also handle HTML img tags
sed -i -E "s|src=\"(\./)?images/|src=\"/images/${POST_SLUG}/|g" "$DEST_FILE"

echo "Image paths updated."

# --- Step 7: Build verification -------------------------------------------------

echo ""
echo "Running Hugo build verification..."
cd "$SITE_DIR"

if hugo --minify 2>&1; then
    echo ""
    echo "Hugo build succeeded."
else
    echo ""
    echo "ERROR: Hugo build failed. Fix errors above before publishing."
    exit 1
fi

# --- Step 8: Show diff ----------------------------------------------------------

echo ""
echo "=== Changes to be committed ==="
git -C "$SITE_DIR" add -N "$DEST_FILE"
[[ -d "$IMG_DEST" ]] && git -C "$SITE_DIR" add -N "$IMG_DEST" 2>/dev/null || true
git -C "$SITE_DIR" diff --stat
echo ""
git -C "$SITE_DIR" diff -- "$DEST_FILE" | head -80
echo ""

# --- Step 9: Confirmation -------------------------------------------------------

read -rp "Publish? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Aborted. File is at ${DEST_FILE} — you can publish manually later."
    exit 0
fi

# --- Step 10: Git add, commit, push ---------------------------------------------

cd "$SITE_DIR"
git add "$DEST_FILE"
[[ -d "$IMG_DEST" ]] && git add "$IMG_DEST" 2>/dev/null || true

COMMIT_MSG="Publish: ${POST_SLUG}"
if $DRAFT; then
    COMMIT_MSG="Draft: ${POST_SLUG}"
fi

git commit -m "$COMMIT_MSG"
git push origin main

echo ""
echo "Published! Post will be live after GitHub Actions deploy completes."
echo "  Post: ${DEST_FILE}"
[[ -d "$IMG_DEST" ]] && echo "  Images: ${IMG_DEST}/"
echo "  URL:  https://rexcoleman.dev/posts/${POST_SLUG}/"

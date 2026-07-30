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
GOVML_DIR="${GOVML_DIR:-${HOME}/ml-governance-templates}"
VALIDATE_CONTENT="${GOVML_DIR}/scripts/validate_content.sh"
CLAIM_TAG_PATTERN='\[([[:space:]]*(HYPOTHESIZED|DEMONSTRATED|SUGGESTED|VALIDATED|ASSUMED|APPROXIMATE|PROJECTED)([[:space:]]*,[[:space:]]*(HYPOTHESIZED|DEMONSTRATED|SUGGESTED|VALIDATED|ASSUMED|APPROXIMATE|PROJECTED))*[[:space:]]*)\]|\[SEED:'

# Registered proof mode bypasses only interactive staging and external effects.
# It is available solely from an isolated /tmp site worktree and still crosses
# the production BLG-08 final-byte mount used by the ordinary publish path.
if [[ "${1:-}" == "--registered-proof-source" ]]; then
    if [[ "$#" -ne 3 ]]; then
        echo "REFUSE(REGISTERED_PROOF_ARGUMENTS): expected source and destination" >&2
        exit 3
    fi
    PROOF_SOURCE="$(realpath "$2")"
    PROOF_DESTINATION="$(realpath -m "$3")"
    case "$SITE_DIR" in
        /tmp/*) ;;
        *)
            echo "REFUSE(ISOLATED_SITE_WORKTREE_REQUIRED): ${SITE_DIR}" >&2
            exit 3
            ;;
    esac
    case "$PROOF_SOURCE:$PROOF_DESTINATION" in
        /tmp/*:/tmp/*) ;;
        *)
            echo "REFUSE(TEMP_PROOF_PATHS_REQUIRED)" >&2
            exit 3
            ;;
    esac
    if [[ ! -f "$PROOF_SOURCE" || -L "$PROOF_SOURCE" || -e "$PROOF_DESTINATION" \
          || ! -d "$(dirname "$PROOF_DESTINATION")" ]]; then
        echo "REFUSE(REGISTERED_PROOF_PRECONDITION)" >&2
        exit 3
    fi
    python3 "$SITE_DIR/scripts/blog_publish_mount.py" \
        "$PROOF_SOURCE" "$PROOF_DESTINATION"
    echo "BLG-08_REGISTERED_PROOF_EFFECT_COMMITTED ${PROOF_DESTINATION}"
    exit 0
fi

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

CURRENT_BRANCH="$(git -C "$SITE_DIR" branch --show-current)"
case "$CURRENT_BRANCH" in
    main|master|"")
        echo "Error: publication must start on a named non-main PR branch."
        exit 1
        ;;
    codex/*|feature/*|fix/*) ;;
    *)
        echo "Error: unsupported PR branch '${CURRENT_BRANCH}'."
        exit 1
        ;;
esac

if [[ ! -f "$VALIDATE_CONTENT" ]]; then
    echo "Error: content validator not found at ${VALIDATE_CONTENT}."
    exit 1
fi
bash "$VALIDATE_CONTENT" "$PROJECT_DIR"

# --- Step 2: Stage final bytes outside the destination --------------------------

DEST_FILE="${CONTENT_DIR}/${POST_SLUG}.md"
FINAL_FILE="$(mktemp)"
trap 'rm -f "$FINAL_FILE"' EXIT
cp "$DRAFT_FILE" "$FINAL_FILE"

# --- Step 3: Add Hugo front matter if not present -------------------------------

has_front_matter() {
    head -1 "$1" | grep -q '^\-\-\-' && return 0 || return 1
}

if ! has_front_matter "$FINAL_FILE"; then
    echo ""
    echo "No Hugo front matter detected. Let's add it."
    read -rp "Post title: " POST_TITLE

    # Extract candidate tags from content (words after # headers, code fences lang hints)
    CANDIDATE_TAGS=$(grep -oP '(?<=^## ).*|(?<=^### ).*' "$FINAL_FILE" \
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
    cat "$FINAL_FILE" >> "$TMPFILE"
    mv "$TMPFILE" "$FINAL_FILE"

    echo "Front matter added."
else
    echo "Front matter already present."
    # Step 6: If --draft flag, force draft: true in existing front matter
    if $DRAFT; then
        if grep -q '^draft:' "$FINAL_FILE"; then
            sed -i 's/^draft:.*/draft: true/' "$FINAL_FILE"
        else
            # Insert draft: true after the first ---
            sed -i '0,/^---$/!{/^---$/!{/^title:/a draft: true
}}' "$FINAL_FILE"
        fi
        echo "Set draft: true"
    fi
fi

# --- Step 4: Construct the exact final post bytes ------------------------------

IMG_SRC="${PROJECT_DIR}/blog/images"
IMG_DEST="${STATIC_DIR}/${POST_SLUG}"

# Replace relative image paths with Hugo static paths
# Handles: ![alt](images/foo.png) and ![alt](./images/foo.png)
sed -i -E "s|\((\./)?images/|\(/images/${POST_SLUG}/|g" "$FINAL_FILE"

# Also handle HTML img tags
sed -i -E "s|src=\"(\./)?images/|src=\"/images/${POST_SLUG}/|g" "$FINAL_FILE"

echo "Image paths updated."

FINAL_INTERNAL_TAGS=$(grep -cE "$CLAIM_TAG_PATTERN" "$FINAL_FILE" 2>/dev/null || echo 0)
if [[ "$FINAL_INTERNAL_TAGS" -ne 0 ]]; then
    echo "Error: ${FINAL_INTERNAL_TAGS} internal claim tag(s) remain in final post bytes."
    exit 1
fi

read -rp "Publish? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Aborted before destination write."
    exit 0
fi

# The Hugo destination is unreachable until the exact final bytes above are
# admitted and their one-attempt authorization is consumed.
MOUNT_RECEIPT="$(
    python3 "$SITE_DIR/scripts/blog_publish_mount.py" \
        "$FINAL_FILE" "$DEST_FILE" --image-source "$IMG_SRC"
)"
ADMISSION_RELATIVE="$(
    python3 -c 'import json,sys; value=json.loads(sys.argv[1]); print(next(row["path"] for row in value["target"]["members"] if row["path"].startswith(".rea/c3/hybrid-subject-manifests/")))' \
        "$MOUNT_RECEIPT"
)"
echo "BLG-08 exact bundle and deterministic subject manifest committed: ${ADMISSION_RELATIVE}"

if [[ "${REA_WRITE_INTEGRITY_PRE_EXTERNAL_ONLY:-0}" == "1" ]]; then
    echo "BLG-08 local Hugo effect committed; PRE_EXTERNAL_BOUNDARY"
    exit 0
fi

# Images were members of the same exact BLG-08 bundle as the post.
if [[ -d "$IMG_DEST" ]] && [[ -n "$(ls -A "$IMG_DEST" 2>/dev/null)" ]]; then
    IMG_COUNT=$(find "$IMG_DEST" -type f | wc -l)
    echo "Committed ${IMG_COUNT} exact image member(s) to ${IMG_DEST}/"
else
    echo "No images found at ${IMG_SRC}/ — skipping."
fi

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

# --- Step 10: Git add, commit, push ---------------------------------------------

cd "$SITE_DIR"
git add "$DEST_FILE"
[[ -d "$IMG_DEST" ]] && git add "$IMG_DEST" 2>/dev/null || true
git add "$SITE_DIR/$ADMISSION_RELATIVE"

COMMIT_MSG="Publish: ${POST_SLUG}"
if $DRAFT; then
    COMMIT_MSG="Draft: ${POST_SLUG}"
fi

git commit -m "$COMMIT_MSG"
python3 "$SITE_DIR/scripts/rex_release.py" push

echo ""
echo "PRE_MAIN_BOUNDARY: exact PR branch commit pushed."
echo "Open a pull request to protected main; one distinct approval is required."
echo "Publication and deployment are not established until protected merge and BLG-10."
echo "  Post: ${DEST_FILE}"
[[ -d "$IMG_DEST" ]] && echo "  Images: ${IMG_DEST}/"
echo "  URL:  https://rexcoleman.dev/posts/${POST_SLUG}/"

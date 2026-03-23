#!/usr/bin/env bash
# validate_post.sh — Pre-publish governance check for rexcoleman.dev
# Catches: ghost image counts, missing sections, bio drift, broken links
# Usage: ./validate_post.sh [path/to/post.md] or ./validate_post.sh --all

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check() {
    local desc="$1" result="$2"
    if [ "$result" = "PASS" ]; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    elif [ "$result" = "WARN" ]; then
        echo -e "  ${YELLOW}WARN${NC} $desc"
        WARN=$((WARN + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

validate_post() {
    local file="$1"
    local basename=$(basename "$file")
    echo ""
    echo "=== Validating: $basename ==="

    # Extract front matter
    local format
    format=$(grep -m1 'format:' "$file" | sed 's/.*format: *"\?\([^"]*\)"\?.*/\1/' || true)
    local image_count
    image_count=$(grep -m1 'image_count:' "$file" | sed 's/.*image_count: *\([0-9][0-9]*\).*/\1/' || true)
    image_count="${image_count:-0}"
    local audience_side
    audience_side=$(grep -m1 'audience_side:' "$file" | sed 's/.*audience_side: *"\?\([^"]*\)"\?.*/\1/' || true)

    # Check format tag exists
    [ -n "$format" ] && check "format: tag present ($format)" "PASS" || check "format: tag MISSING" "FAIL"

    # Check audience_side exists
    [ -n "$audience_side" ] && check "audience_side: present ($audience_side)" "PASS" || check "audience_side: MISSING" "FAIL"

    # Check description exists
    local desc=$(grep -m1 'description:' "$file" | sed 's/.*description: *"\?\(.*\)"\?/\1/' || true)
    [ -n "$desc" ] && check "description: present" "PASS" || check "description: MISSING" "WARN"

    # Check image_count matches actual images
    local actual_images
    actual_images=$(grep -c '!\[' "$file" 2>/dev/null || true)
    actual_images="${actual_images:-0}"
    if [ "$image_count" = "$actual_images" ]; then
        check "image_count: $image_count matches actual ($actual_images)" "PASS"
    else
        check "image_count: $image_count but actual images: $actual_images (MISMATCH)" "FAIL"
    fi

    # Count text diagrams (ASCII art in code blocks: ┌, ├, └, │, ─, →, ▼)
    local has_text_diagram=0
    grep -qE '[┌├└│─→▼]' "$file" 2>/dev/null && has_text_diagram=1
    local visual_count=$((actual_images + has_text_diagram))

    # R26: Image minimum per format (images OR text diagrams count)
    case "$format" in
        technical-blog|tutorial)
            [ "$visual_count" -ge 1 ] && check "R26: >=1 visual for $format ($actual_images images + $has_text_diagram text diagrams)" "PASS" || check "R26: $format requires >=1 visual, has $visual_count" "FAIL"
            ;;
    esac

    # R25: Required sections per format
    case "$format" in
        technical-blog)
            grep -qi 'limitation' "$file" && check "R25: Limitations section present" "PASS" || check "R25: Limitations section MISSING" "FAIL"
            grep -qi "what's next\|what i'm doing" "$file" && check "R25: What's Next present" "PASS" || check "R25: What's Next MISSING" "FAIL"
            ;;
        tutorial)
            grep -qi "not solved\|limitation\|isn't solved" "$file" && check "R25: What's Not Solved present" "PASS" || check "R25: What's Not Solved MISSING" "FAIL"
            ;;
        perspective)
            grep -qi "what i'm doing\|what we're doing" "$file" && check "R25: What I'm Doing About It present" "PASS" || check "R25: What I'm Doing MISSING" "FAIL"
            ;;
    esac

    # Bio footer check (exact canonical phrase)
    grep -q "at every layer of the stack" "$file" && check "Standard bio footer present (canonical)" "PASS" || check "Standard bio footer MISSING or non-canonical (must contain 'at every layer of the stack')" "FAIL"

    # Substack CTA
    grep -qi "substack" "$file" && check "Substack CTA present" "PASS" || check "Substack CTA MISSING" "FAIL"

    # Broken links check (trailing hyphen)
    grep -q 'vuln-prioritization-ml-[^a-z]' "$file" && check "Broken repo URL (trailing hyphen)" "FAIL" || check "No broken repo URLs" "PASS"

    # Cross-post freshness check (R29)
    local slug=$(basename "$file" .md)
    local cross_dir="cross-posts"
    if [ -d "$cross_dir" ]; then
        for variant in "${cross_dir}/${slug}_"*.{md,txt} ; do
            if [ -f "$variant" ] && [ "$file" -nt "$variant" ]; then
                check "R29: cross-post $(basename $variant) may be stale (source newer)" "WARN"
            fi
        done
    fi

    # --- R55: govML Private Repo Check ---
    if grep -qi "github.com/rexcoleman/govML\|github.com/rexcoleman/ml-governance-templates\|git clone.*govML\|pip install govml" "$file"; then
        echo -e "  ${RED}FAIL${NC}: R55 violation — contains prohibited govML repo reference"
        FAIL=$((FAIL + 1))
    else
        PASS=$((PASS + 1))
    fi

    # --- R58: Content Routing Check ---
    FORMAT=$(grep -m1 '^format:' "$file" | sed 's/format:[[:space:]]*//' | tr -d '"')
    FILEPATH="$file"
    if [[ "$FORMAT" == "til" ]] && [[ "$FILEPATH" == *"/posts/"* ]]; then
        echo -e "  ${RED}FAIL${NC}: R58 violation — TIL format content must not be in /posts/ (route to social channels)"
        FAIL=$((FAIL + 1))
    else
        PASS=$((PASS + 1))
    fi

    # --- R55: govML Private Repo Check ---
    if grep -qi "github.com/rexcoleman/govML\|github.com/rexcoleman/ml-governance" "$file" 2>/dev/null; then
        echo -e "  ${RED}FAIL${NC}: R55 violation — public govML repo link found (repo is PRIVATE)"
        FAIL=$((FAIL + 1))
    else
        PASS=$((PASS + 1))
    fi

    # --- R56: Readability Check (LL-118) ---
    READABILITY_SCRIPT="$HOME/ml-governance-templates/scripts/generators/gen_readability_check.py"
    if [ -f "$READABILITY_SCRIPT" ]; then
        if python3 "$READABILITY_SCRIPT" "$file" > /dev/null 2>&1; then
            echo -e "  ${GREEN}PASS${NC}: Readability check passed (R56)"
            PASS=$((PASS + 1))
        else
            echo -e "  ${YELLOW}WARN${NC}: Readability check has issues (R56)"
            WARN=$((WARN + 1))
        fi
    fi

    # --- R57: Channel Voice Check (LL-118) ---
    VOICE_SCRIPT="$HOME/ml-governance-templates/scripts/generators/gen_channel_voice_check.py"
    if [ -f "$VOICE_SCRIPT" ]; then
        VOICE_OUTPUT=$(python3 "$VOICE_SCRIPT" "$file" blog 2>&1)
        VOICE_SCORE=$(echo "$VOICE_OUTPUT" | grep -oP 'Voice-Fit Score:\s*\K\d+' || echo "0")
        if [ "$VOICE_SCORE" -ge 70 ] 2>/dev/null; then
            echo -e "  ${GREEN}PASS${NC}: Voice check passed — score $VOICE_SCORE/100 (R57)"
            PASS=$((PASS + 1))
        else
            echo -e "  ${YELLOW}WARN${NC}: Voice check — score $VOICE_SCORE/100 (R57)"
            WARN=$((WARN + 1))
        fi
    fi
}

# Main
if [ "${1:-}" = "--all" ]; then
    for f in content/posts/*.md; do
        [ -f "$f" ] && [[ "$(basename "$f")" != "_index.md" ]] && validate_post "$f"
    done
else
    for f in "$@"; do
        validate_post "$f"
    done
fi

echo ""
echo "=== Summary: $PASS PASS, $FAIL FAIL, $WARN WARN ==="
[ "$FAIL" -gt 0 ] && exit 1 || exit 0

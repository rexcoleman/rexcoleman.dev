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
        research-report)
            [ "$actual_images" -ge 3 ] && check "R26: >=3 images for research-report" "PASS" || check "R26: research-report requires >=3 images, has $actual_images" "WARN"
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

    # Bio footer check
    grep -q "securing AI from the architecture up" "$file" && check "Standard bio footer present" "PASS" || check "Standard bio footer MISSING or non-standard" "FAIL"

    # Substack CTA
    grep -qi "substack" "$file" && check "Substack CTA present" "PASS" || check "Substack CTA MISSING" "FAIL"

    # Broken links check (trailing hyphen)
    grep -q 'vuln-prioritization-ml-[^a-z]' "$file" && check "Broken repo URL (trailing hyphen)" "FAIL" || check "No broken repo URLs" "PASS"
}

# Main
if [ "${1:-}" = "--all" ]; then
    for f in content/posts/*.md content/research/*.md content/til/*.md; do
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

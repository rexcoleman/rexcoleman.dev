#!/usr/bin/env python3
"""
cross-post.py — Generate platform-specific versions of a Hugo blog post.

Usage:
    python cross-post.py content/posts/agent-redteam.md

Output:
    cross-posts/<slug>_devto.md      (dev.to with canonical_url front matter)
    cross-posts/<slug>_linkedin.txt  (plain text summary + link, <1300 chars)
    cross-posts/<slug>_reddit.md     (Reddit markdown, no images, link at top)
"""

import argparse
import os
import re
import sys
import textwrap
from pathlib import Path


SITE_URL = "https://rexcoleman.dev"


def strip_front_matter(text: str) -> tuple[dict, str]:
    """Remove YAML front matter and return (metadata dict, body)."""
    metadata = {}
    body = text

    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            raw_meta = parts[1].strip()
            body = parts[2].strip()

            for line in raw_meta.splitlines():
                line = line.strip()
                if ":" in line and not line.startswith("-"):
                    key, _, val = line.partition(":")
                    val = val.strip().strip('"').strip("'")
                    if val:
                        metadata[key.strip()] = val

    return metadata, body


def extract_tags(metadata: dict, body: str) -> list[str]:
    """Extract tags from front matter or generate from headings."""
    # Check front matter for tags
    if "tags" in metadata:
        raw = metadata["tags"]
        # Handle inline YAML list: [a, b, c]
        if raw.startswith("["):
            return [t.strip().strip('"').strip("'") for t in raw[1:-1].split(",")]
        return [raw]

    # Fall back: extract from h2 headings
    headings = re.findall(r"^## (.+)$", body, re.MULTILINE)
    tags = []
    for h in headings[:5]:
        word = re.sub(r"[^a-z0-9 ]", "", h.lower()).strip()
        if word and len(word) < 30:
            tags.append(word.replace(" ", ""))
    return tags[:5]


def extract_paragraphs(body: str) -> list[str]:
    """Extract non-empty paragraphs (skip headings, code blocks, images)."""
    paragraphs = []
    in_code_block = False

    for line in body.split("\n\n"):
        line = line.strip()
        if line.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue
        if not line:
            continue
        if line.startswith("#"):
            continue
        if line.startswith("!["):
            continue
        if line.startswith("<img"):
            continue
        if line.startswith("|"):
            continue
        # Must have actual text content
        clean = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        clean = re.sub(r"[*_`~]", "", clean).strip()
        if len(clean) > 40:
            paragraphs.append(clean)

    return paragraphs


def find_key_finding(body: str) -> str:
    """Try to extract a key finding or result sentence."""
    patterns = [
        r"(?:key finding|result|discovered|achieved|found that)[:\s]+(.+?)(?:\.|$)",
        r"(?:TL;DR|Summary)[:\s]+(.+?)(?:\.|$)",
    ]
    for pat in patterns:
        match = re.search(pat, body, re.IGNORECASE)
        if match:
            return match.group(1).strip() + "."

    # Fall back: find a sentence with a number (likely a result)
    for para in extract_paragraphs(body):
        if re.search(r"\d+[%x]|\d+\.\d+", para):
            sentences = re.split(r"(?<=[.!?])\s+", para)
            for s in sentences:
                if re.search(r"\d+[%x]|\d+\.\d+", s):
                    return s.strip()

    return ""


def generate_devto(slug: str, metadata: dict, body: str) -> str:
    """Generate dev.to version with canonical_url front matter."""
    title = metadata.get("title", slug.replace("-", " ").title())
    tags = extract_tags(metadata, body)
    canonical = f"{SITE_URL}/posts/{slug}/"

    # dev.to limits to 4 tags, each max 20 chars, alphanumeric + hyphens
    devto_tags = []
    for t in tags[:4]:
        clean = re.sub(r"[^a-z0-9]", "", t.lower())
        if clean:
            devto_tags.append(clean[:20])

    front_matter = f"""---
title: "{title}"
published: true
canonical_url: "{canonical}"
tags: [{', '.join(devto_tags)}]
---"""

    return f"{front_matter}\n\n{body}\n"


def generate_linkedin(slug: str, metadata: dict, body: str) -> str:
    """Generate LinkedIn plain text summary (<1300 chars)."""
    title = metadata.get("title", slug.replace("-", " ").title())
    url = f"{SITE_URL}/posts/{slug}/"

    paragraphs = extract_paragraphs(body)
    key_finding = find_key_finding(body)

    # Build the post
    parts = [title, ""]

    # First 2 paragraphs
    for p in paragraphs[:2]:
        # Truncate long paragraphs
        if len(p) > 300:
            p = p[:297] + "..."
        parts.append(p)
        parts.append("")

    # Key finding
    if key_finding:
        parts.append(f"Key finding: {key_finding}")
        parts.append("")

    parts.append(f"Full post: {url}")

    text = "\n".join(parts)

    # Enforce 1300 char limit
    if len(text) > 1300:
        # Trim paragraphs
        while len(text) > 1300 and len(parts) > 4:
            parts.pop(-3)  # Remove from middle, keep title + link
            text = "\n".join(parts)

        if len(text) > 1300:
            text = text[:1297] + "..."

    return text


def generate_reddit(slug: str, metadata: dict, body: str) -> str:
    """Generate Reddit markdown: no images, link at top."""
    title = metadata.get("title", slug.replace("-", " ").title())
    url = f"{SITE_URL}/posts/{slug}/"

    header = f"**[Full post with images and code]({url})**\n\n---\n"

    # Remove image lines
    cleaned = re.sub(r"!\[[^\]]*\]\([^)]+\)\n?", "", body)
    # Remove HTML img tags
    cleaned = re.sub(r"<img[^>]+>\n?", "", cleaned)
    # Remove empty lines left by image removal (collapse triple+ newlines)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)

    return f"# {title}\n\n{header}\n{cleaned.strip()}\n"


def main():
    parser = argparse.ArgumentParser(
        description="Generate cross-platform versions of a Hugo blog post."
    )
    parser.add_argument("post", help="Path to Hugo post markdown file")
    args = parser.parse_args()

    post_path = Path(args.post)
    if not post_path.exists():
        print(f"Error: {post_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    # Derive slug from filename
    slug = post_path.stem

    # Read source
    text = post_path.read_text(encoding="utf-8")
    metadata, body = strip_front_matter(text)

    # Create output directory
    site_dir = Path(__file__).resolve().parent
    out_dir = site_dir / "cross-posts"
    out_dir.mkdir(exist_ok=True)

    # Generate all versions
    devto = generate_devto(slug, metadata, body)
    linkedin = generate_linkedin(slug, metadata, body)
    reddit = generate_reddit(slug, metadata, body)

    # Write output files
    devto_path = out_dir / f"{slug}_devto.md"
    linkedin_path = out_dir / f"{slug}_linkedin.txt"
    reddit_path = out_dir / f"{slug}_reddit.md"

    devto_path.write_text(devto, encoding="utf-8")
    linkedin_path.write_text(linkedin, encoding="utf-8")
    reddit_path.write_text(reddit, encoding="utf-8")

    print(f"Generated cross-post files in {out_dir}/:")
    print(f"  {devto_path.name:<30} ({len(devto):>5} chars)  — dev.to")
    print(f"  {linkedin_path.name:<30} ({len(linkedin):>5} chars)  — LinkedIn")
    print(f"  {reddit_path.name:<30} ({len(reddit):>5} chars)  — Reddit")

    if len(linkedin) > 1300:
        print(f"\n  WARNING: LinkedIn version is {len(linkedin)} chars (limit: 1300)")


if __name__ == "__main__":
    main()

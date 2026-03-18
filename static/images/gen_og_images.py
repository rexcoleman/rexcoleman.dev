#!/usr/bin/env python3
"""
OG Image Generator — Rex Coleman Design System v2
==================================================
Generates branded 1200x630 social preview images for all blog posts.

Design system:
  - Background: #0C111C (deep navy, not pure black)
  - Accent: #00E0A0 (vivid mint, cybersecurity-coded)
  - Typography: Lato (titles), DejaVu Sans Mono (tags)
  - Layout: left accent bar, tag pill, title, stat bar, footer

Usage:
  python3 gen_og_images.py

Dependencies:
  pip install Pillow

Research basis:
  - Dark navy backgrounds for developer/cybersecurity brands (webportfolios.dev)
  - OG images: 1200x630, center key elements, <60 char title (krumzi.com)
  - Visual hierarchy: title 2-3x subtitle, left-aligned (ixdf.org)
  - Vercel Geist: minimal, typography-driven, no decoration (vercel.com/geist)
  - Dark mode: avoid pure black, use #121212+ range (smashingmagazine.com)
  - Cybersecurity palette: dark bg + high-contrast cyan/mint accent (produkto.io)
"""

from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.dirname(os.path.abspath(__file__))

# ============================================================
# DESIGN TOKENS
# ============================================================

# Colors
BG        = (12, 17, 28)       # #0C111C  deep navy
SURFACE   = (18, 25, 42)       # #12192A  card surface
ACCENT    = (0, 224, 160)      # #00E0A0  vivid mint
ACCENT_DIM= (0, 160, 114)      # #00A072  muted mint
WHITE     = (237, 240, 245)    # #EDF0F5  off-white
GRAY      = (130, 142, 163)    # #828EA3  mid-gray
DIM       = (50, 58, 78)       # #323A4E  separator
TAG_BG    = (22, 32, 52)       # #162034  tag pill bg
FOOTER_BG = (8, 12, 22)        # #080C16  footer bar

# Typography
TITLE_FONT   = ImageFont.truetype("/usr/share/fonts/truetype/lato/Lato-Black.ttf", 56)
SUB_FONT     = ImageFont.truetype("/usr/share/fonts/truetype/lato/Lato-Bold.ttf", 28)
STAT_FONT    = ImageFont.truetype("/usr/share/fonts/truetype/lato/Lato-Heavy.ttf", 32)
NAME_FONT    = ImageFont.truetype("/usr/share/fonts/truetype/lato/Lato-Bold.ttf", 22)
CRED_FONT    = ImageFont.truetype("/usr/share/fonts/truetype/lato/Lato-Regular.ttf", 18)
TAG_FONT     = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 16)
FOOTER_FONT  = ImageFont.truetype("/usr/share/fonts/truetype/lato/Lato-Regular.ttf", 18)

# Layout
W, H = 1200, 630
PAD_L = 72
PAD_R = 72
ACCENT_BAR_W = 5
FOOTER_H = 44
SEP_Y = 108


def draw_subtle_grid(draw, opacity=8):
    """Subtle dot grid for visual texture."""
    for x in range(0, W, 40):
        for y in range(0, H - FOOTER_H, 40):
            c = (BG[0] + opacity, BG[1] + opacity, BG[2] + opacity)
            draw.point((x, y), fill=c)


def make_og(filename, title_lines, stats, tag, description=None):
    """
    Create a branded 1200x630 OG image.

    Args:
        filename: output filename (saved to same directory as this script)
        title_lines: list of 1-2 strings for the main title
        stats: list of (value, label) tuples for the stat bar
        tag: category tag string (e.g., "AGENT SECURITY")
        description: optional subtitle line below title
    """
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    draw_subtle_grid(draw)
    draw.rectangle([0, 0, ACCENT_BAR_W, H], fill=ACCENT)

    # Header
    draw.text((PAD_L, 32), "Rex Coleman", font=NAME_FONT, fill=ACCENT)
    draw.text((PAD_L, 60), "CISSP  \u00b7  CFA  \u00b7  MSCS Georgia Tech", font=CRED_FONT, fill=GRAY)
    draw.line([(PAD_L, SEP_Y), (W - PAD_R, SEP_Y)], fill=DIM, width=1)

    # Tag pill
    tag_y = SEP_Y + 20
    tag_bbox = draw.textbbox((0, 0), tag, font=TAG_FONT)
    tag_w = tag_bbox[2] - tag_bbox[0]
    tag_h = tag_bbox[3] - tag_bbox[1]
    ppx, ppy = 14, 8
    draw.rounded_rectangle(
        [PAD_L, tag_y, PAD_L + tag_w + ppx * 2, tag_y + tag_h + ppy * 2],
        radius=4, fill=TAG_BG, outline=DIM, width=1
    )
    draw.text((PAD_L + ppx, tag_y + ppy), tag, font=TAG_FONT, fill=ACCENT)

    # Title
    title_y = tag_y + tag_h + ppy * 2 + 24
    for i, line in enumerate(title_lines):
        draw.text((PAD_L, title_y + i * 68), line, font=TITLE_FONT, fill=WHITE)

    # Description
    content_bottom = title_y + len(title_lines) * 68
    if description:
        content_bottom += 12
        draw.text((PAD_L, content_bottom), description, font=SUB_FONT, fill=GRAY)
        content_bottom += 36

    # Stat bar
    if stats:
        stat_y = max(content_bottom + 28, 430)
        stat_x = PAD_L
        for i, (value, label) in enumerate(stats):
            draw.text((stat_x, stat_y), str(value), font=STAT_FONT, fill=ACCENT)
            vw = draw.textbbox((0, 0), str(value), font=STAT_FONT)[2]
            draw.text((stat_x + vw + 8, stat_y + 6), label, font=CRED_FONT, fill=GRAY)
            lw = draw.textbbox((0, 0), label, font=CRED_FONT)[2]
            stat_x += vw + 8 + lw + 48
            if i < len(stats) - 1:
                draw.line([(stat_x - 24, stat_y + 4), (stat_x - 24, stat_y + 30)], fill=DIM, width=1)

    # Footer
    draw.rectangle([0, H - FOOTER_H, W, H], fill=FOOTER_BG)
    draw.text((PAD_L, H - FOOTER_H + 12), "rexcoleman.dev", font=FOOTER_FONT, fill=ACCENT)
    tagline = "Securing AI From The Architecture Up"
    tw = draw.textbbox((0, 0), tagline, font=FOOTER_FONT)[2]
    draw.text((W - PAD_R - tw, H - FOOTER_H + 12), tagline, font=FOOTER_FONT, fill=GRAY)

    img.save(os.path.join(OUT, filename), "PNG", optimize=True)
    print(f"  {filename}")


if __name__ == "__main__":
    print("Generating OG images (design system v2)...\n")

    make_og("og-default.png",
        ["Securing AI From", "The Architecture Up"],
        [("9", "projects"), ("4", "ML paradigms"), ("469+", "tests")],
        "AI SECURITY ARCHITECTURE")

    make_og("og-agent-redteam.png",
        ["I Red-Teamed AI Agents:", "Here's How They Break"],
        [("100%", "hijack rate"), ("19", "attacks"), ("$2", "total cost")],
        "AGENT SECURITY")

    make_og("og-adversarial-control-analysis.png",
        ["One Principle,", "Six Domains"],
        [("6", "domains"), ("1", "principle"), ("35%", "attack reduction")],
        "METHODOLOGY",
        description="Adversarial Control Analysis for AI Security")

    make_og("og-rl-agent-vulnerability.png",
        ["Beyond Prompt Injection:", "RL Attacks on AI Agents"],
        [("40", "agents"), ("4", "attack classes"), ("20-50x", "degradation")],
        "REINFORCEMENT LEARNING")

    make_og("og-secure-openclaw.png",
        ["How to Secure Your", "OpenClaw in 30 Minutes"],
        [("5", "risks"), ("30", "minutes"), ("step-by-step", "guide")],
        "TUTORIAL")

    make_og("og-cvss-gets-it-wrong.png",
        ["Why CVSS Gets It Wrong"],
        [("338K", "CVEs"), ("+24pp", "vs CVSS"), ("SHAP", "explainability")],
        "VULNERABILITY MANAGEMENT",
        description="ML-Powered Vulnerability Prioritization")

    make_og("og-adversarial-ids.png",
        ["Adversarial ML on", "Network Intrusion Detection"],
        [("57", "attacker features"), ("14", "defender features"), ("100%", "noise detection")],
        "ADVERSARIAL ML")

    make_og("og-model-fingerprinting.png",
        ["Antivirus for AI Models"],
        [("6", "detectors"), ("5", "representations"), ("30", "combinations")],
        "MODEL SUPPLY CHAIN",
        description="Behavioral Fingerprinting Detects What Static Analysis Misses")

    make_og("og-govml-methodology.png",
        ["How I Govern", "AI-Assisted ML Projects"],
        [("42", "templates"), ("19", "generators"), ("9", "projects")],
        "ML GOVERNANCE")

    make_og("og-third-party-skills.png",
        ["Why Third-Party Skills Are", "the Biggest Attack Vector"],
        [("820+", "malicious skills"), ("20%", "of registry"), ("24/7", "execution")],
        "AGENT SUPPLY CHAIN")

    print("\nDone. 10 images generated.")

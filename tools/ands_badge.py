#!/usr/bin/env python3
"""ands_badge.py — Generate a professional SVG badge for an ANDS score.

Usage:
  python3 tools/ands_badge.py 2.1.1.1.3 --out badge.svg
"""

import argparse
import sys

def generate_svg(ands_code: str, label: str = "ANDS") -> str:
    """Generate a flat-style SVG badge."""
    # Determine color based on Risk (R) axis (last digit)
    try:
        r_val = int(ands_code.split('.')[-1])
    except (ValueError, IndexError):
        r_val = 3

    # Professional color palette
    if r_val >= 5:
        color = "#e05d44" # Red (Critical)
    elif r_val >= 4:
        color = "#dfb317" # Amber (High)
    elif r_val >= 3:
        color = "#4c1"    # Green (Moderate)
    else:
        color = "#97ca00" # Bright Green (Low)

    # Calculate widths based on text length (rough estimation)
    label_w = len(label) * 8 + 10
    value_w = len(ands_code) * 8 + 10
    total_w = label_w + value_w

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{total_w}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="{total_w}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h{label_w}v20H0z"/>
    <path fill="{color}" d="M{label_w} 0h{value_w}v20H{label_w}z"/>
    <path fill="url(#b)" d="M0 0h{total_w}v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="{label_w * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{label_w * 10 - 100}">{label}</text>
    <text x="{label_w * 5}" y="140" transform="scale(.1)" textLength="{label_w * 10 - 100}">{label}</text>
    <text x="{(label_w + value_w / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{value_w * 10 - 100}">{ands_code}</text>
    <text x="{(label_w + value_w / 2) * 10}" y="140" transform="scale(.1)" textLength="{value_w * 10 - 100}">{ands_code}</text>
  </g>
</svg>"""
    return svg

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ands", help="ANDS code (e.g., 2.1.2.1.3)")
    ap.add_argument("--label", default="ANDS", help="Badge label (default: ANDS)")
    ap.add_argument("--out", default="ands-badge.svg", help="Output filename")
    args = ap.parse_args()

    svg = generate_svg(args.ands, args.label)
    try:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"Successfully generated badge: {args.out}")
    except Exception as e:
        print(f"Error writing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SolanaShield MCP — Pitch Video Generator
Creates a professional 3-minute pitch video from slides
Uses Pillow for rendering + MoviePy for video assembly
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
    from moviepy import ImageClip, TextClip, CompositeVideoClip, concatenate_videoclips, AudioFileClip
except ImportError:
    print("Installing deps...")
    os.system("pip3 install --user --break-system-packages Pillow moviepy")
    from PIL import Image, ImageDraw, ImageFont
    from moviepy import ImageClip, TextClip, CompositeVideoClip, concatenate_videoclips

W, H = 1920, 1080
OUTPUT_DIR = Path(__file__).parent / "pitch_assets"
OUTPUT_DIR.mkdir(exist_ok=True)

# Color palette
BG_DARK = (15, 12, 41)       # Deep purple-black
BG_MID = (25, 20, 60)        # Mid purple
ACCENT = (124, 58, 237)      # Vivid purple
ACCENT2 = (6, 182, 212)      # Cyan
RED = (239, 68, 68)          # Warning red
GREEN = (34, 197, 94)        # Success green
WHITE = (255, 255, 255)
GRAY = (156, 163, 175)
YELLOW = (250, 204, 21)


def get_font(size, bold=False):
    """Get best available font."""
    paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def gradient_bg(draw, w, h, color1=BG_DARK, color2=BG_MID):
    """Draw gradient background."""
    for y in range(h):
        r = int(color1[0] + (color2[0] - color1[0]) * y / h)
        g = int(color1[1] + (color2[1] - color1[1]) * y / h)
        b = int(color1[2] + (color2[2] - color1[2]) * y / h)
        draw.line([(0, y), (w, y)], fill=(r, g, b))


def draw_centered(draw, text, y, font, fill=WHITE):
    """Draw centered text."""
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    draw.text(((W - tw) // 2, y), text, font=font, fill=fill)


def draw_code_box(draw, text, x, y, w, h, font):
    """Draw terminal-style code box."""
    draw.rounded_rectangle([x, y, x+w, y+h], radius=12, fill=(30, 30, 50), outline=ACCENT)
    # Terminal dots
    for i, c in enumerate([(RED), (YELLOW), (GREEN)]):
        draw.ellipse([x+15+i*25, y+12, x+27+i*25, y+24], fill=c)
    draw.text((x+20, y+40), text, font=font, fill=GREEN)


def slide_title():
    """Slide 1: Title — SolanaShield MCP"""
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    gradient_bg(draw, W, H)

    # Shield icon (simple geometric)
    cx, cy = W//2, 300
    points = [(cx, cy-80), (cx+70, cy-40), (cx+70, cy+40), (cx, cy+80), (cx-70, cy+40), (cx-70, cy-40)]
    draw.polygon(points, fill=ACCENT, outline=ACCENT2)
    draw.polygon([(cx, cy-50), (cx+40, cy-20), (cx+40, cy+20), (cx, cy+50), (cx-40, cy+20), (cx-40, cy-20)], fill=BG_DARK)
    # Lock inside
    draw.rectangle([cx-12, cy-5, cx+12, cy+15], fill=ACCENT2)
    draw.arc([cx-10, cy-20, cx+10, cy], 0, 360, fill=ACCENT2, width=3)

    draw_centered(draw, "SolanaShield MCP", 420, get_font(72, True))
    draw_centered(draw, "Pay-Per-Audit Security for AI Agents", 510, get_font(36), ACCENT2)

    draw_centered(draw, "Colosseum Frontier 2026  |  Track: Infrastructure", 650, get_font(28), GRAY)

    # Stats bar
    stats = [("12", "MCP Tools"), ("40", "Vuln Patterns"), ("$0.01", "Per Audit"), ("x402", "Payments")]
    for i, (num, label) in enumerate(stats):
        sx = 280 + i * 370
        draw.text((sx, 780), num, font=get_font(48, True), fill=ACCENT2)
        draw.text((sx, 840), label, font=get_font(24), fill=GRAY)

    path = OUTPUT_DIR / "slide_01_title.png"
    img.save(path)
    return path


def slide_problem():
    """Slide 2: The Problem — $500M+ Lost"""
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    gradient_bg(draw, W, H, BG_DARK, (40, 15, 25))

    draw_centered(draw, "The Problem", 60, get_font(52, True), RED)

    # Big number
    draw_centered(draw, "$500M+", 170, get_font(96, True), RED)
    draw_centered(draw, "lost to preventable Solana vulnerabilities", 280, get_font(32), GRAY)

    # Three problems
    problems = [
        ("$50K-$200K", "Manual audits cost too much", "Small teams launch unaudited"),
        ("EVM Only", "Existing tools miss Solana", "Wormhole $320M, Mango $114M, Cashio $52M"),
        ("No AI Access", "Agents can't buy security", "Human-in-the-loop: emails, NDAs, invoices"),
    ]
    for i, (title, desc, detail) in enumerate(problems):
        bx = 120 + i * 580
        draw.rounded_rectangle([bx, 400, bx+530, 650], radius=16, fill=(40, 20, 30), outline=RED)
        draw.text((bx+30, 420), title, font=get_font(36, True), fill=RED)
        draw.text((bx+30, 475), desc, font=get_font(24), fill=WHITE)
        draw.text((bx+30, 520), detail, font=get_font(18), fill=GRAY)

    # Bottom stat
    draw_centered(draw, "95% of Solana programs launch WITHOUT a security audit", 750, get_font(30, True), YELLOW)
    draw_centered(draw, "$10B+ TVL at risk", 800, get_font(24), GRAY)

    path = OUTPUT_DIR / "slide_02_problem.png"
    img.save(path)
    return path


def slide_solution():
    """Slide 3: The Solution — SolanaShield + x402"""
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    gradient_bg(draw, W, H, BG_DARK, (10, 30, 45))

    draw_centered(draw, "The Solution", 50, get_font(52, True), GREEN)
    draw_centered(draw, "SolanaShield MCP + x402 Micropayments", 120, get_font(32), ACCENT2)

    # Code demo box
    code = """$ claude
> Audit this Solana program for security issues

[SolanaShield] Scanning... 40 patterns checked in 1.8s

CRITICAL: SOL-C-002 Missing Signer Check
  Line 45: pub fn withdraw(ctx: Context<Withdraw>)
  Impact: Any user can drain funds
  Fix: Add #[account(signer)] constraint

HIGH: SOL-H-001 Missing Owner Validation
  Line 23: No owner check on token account

Found: 2 Critical, 1 High, 3 Medium"""

    draw_code_box(draw, code, 100, 200, 850, 420, get_font(18))

    # x402 flow on right
    draw.text((1020, 210), "x402 Payment Flow", font=get_font(32, True), fill=ACCENT2)

    steps = [
        ("1.", "curl /audit", "Send code to API"),
        ("2.", "402 Payment Required", "Server returns price"),
        ("3.", "Attach USDC header", "Agent pays $0.01-$5"),
        ("4.", "Audit results", "Findings delivered"),
    ]
    for i, (num, title, desc) in enumerate(steps):
        sy = 280 + i * 90
        draw.text((1020, sy), num, font=get_font(28, True), fill=ACCENT)
        draw.text((1060, sy), title, font=get_font(24, True), fill=WHITE)
        draw.text((1060, sy+30), desc, font=get_font(18), fill=GRAY)
        if i < 3:
            draw.text((1035, sy+60), "|", font=get_font(24), fill=ACCENT)

    # Bottom highlight
    draw.rounded_rectangle([200, 700, W-200, 780], radius=12, fill=(20, 50, 40), outline=GREEN)
    draw_centered(draw, "No accounts. No API keys. One payment, one audit.", 720, get_font(28, True), GREEN)

    # Bottom stat
    draw_centered(draw, "Works TODAY with Claude Code, Cursor, and any MCP client", 830, get_font(24), GRAY)

    path = OUTPUT_DIR / "slide_03_solution.png"
    img.save(path)
    return path


def slide_architecture():
    """Slide 4: Architecture + Market"""
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    gradient_bg(draw, W, H)

    draw_centered(draw, "Architecture & Market", 50, get_font(48, True))

    # Architecture boxes
    layers = [
        ("AI Agent / Claude / Cursor", ACCENT, 170),
        ("MCP Protocol", ACCENT2, 270),
        ("SolanaShield Server", GREEN, 370),
        ("40 Patterns | 12 Tools | Rex Engine", YELLOW, 470),
        ("x402 Payment Layer (USDC on Solana)", ACCENT, 570),
    ]
    for label, color, y in layers:
        draw.rounded_rectangle([300, y, W-300, y+70], radius=10, fill=(30, 25, 55), outline=color)
        draw_centered(draw, label, y+18, get_font(28, True), color)
        if y < 570:
            draw_centered(draw, "|", y+75, get_font(24), GRAY)

    # Market stats on right side
    draw.text((1380, 170), "Market", font=get_font(36, True), fill=ACCENT2)
    market = [
        ("$10B+", "Solana TVL"),
        ("95%", "Unaudited"),
        ("100M+", "AI sessions/mo"),
        ("$0.01-$5", "Per audit"),
        ("99%", "Gross margin"),
    ]
    for i, (num, label) in enumerate(market):
        my = 230 + i * 65
        draw.text((1380, my), num, font=get_font(28, True), fill=WHITE)
        draw.text((1540, my+5), label, font=get_font(20), fill=GRAY)

    # Competitive table
    draw.text((100, 700), "vs Competition:", font=get_font(24, True), fill=GRAY)
    comp = [
        ("Trail of Bits", "$50K-$200K", "4-8 weeks", "No MCP", "No x402"),
        ("SolanaShield", "$0.01-$5", "2 seconds", "MCP Native", "x402 Pay"),
    ]
    for i, (name, price, time, mcp, pay) in enumerate(comp):
        cy = 740 + i * 40
        color = GREEN if i == 1 else RED
        draw.text((100, cy), name, font=get_font(22, True), fill=color)
        draw.text((400, cy), price, font=get_font(22), fill=color)
        draw.text((650, cy), time, font=get_font(22), fill=color)
        draw.text((900, cy), mcp, font=get_font(22), fill=color)
        draw.text((1150, cy), pay, font=get_font(22), fill=color)

    path = OUTPUT_DIR / "slide_04_architecture.png"
    img.save(path)
    return path


def slide_traction():
    """Slide 5: Revenue + Traction"""
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    gradient_bg(draw, W, H, BG_DARK, (15, 35, 25))

    draw_centered(draw, "Traction & Revenue", 50, get_font(48, True), GREEN)

    # Traction items
    items = [
        ("npm published", "solanashield-mcp v2.0.0 — install globally", GREEN),
        ("12 MCP Tools", "Full audit, account checks, CPI, PDA, arithmetic, patterns", ACCENT2),
        ("40 Patterns", "Solana-specific: Anchor, SPL, native, rent, PDA seeds", ACCENT2),
        ("x402 Integrated", "Tiered: $0.01 risk-score to $5.00 deep-audit", YELLOW),
        ("Rex Engine v1.1", "116 signatures, 4-pass consensus audit, multi-language", ACCENT),
        ("22+ Products", "Proven shipping: 3 npm packages, 50+ repos, MCP expertise", WHITE),
    ]
    for i, (title, desc, color) in enumerate(items):
        iy = 140 + i * 95
        draw.ellipse([180, iy+5, 200, iy+25], fill=color)
        draw.text((220, iy), title, font=get_font(30, True), fill=color)
        draw.text((220, iy+40), desc, font=get_font(20), fill=GRAY)

    # Roadmap
    draw.text((1100, 140), "Roadmap", font=get_font(32, True), fill=ACCENT2)
    phases = [
        ("Phase 1", "MCP + x402 (NOW)", GREEN),
        ("Phase 2", "Enterprise patterns", YELLOW),
        ("Phase 3", "Audit marketplace", ACCENT),
    ]
    for i, (phase, desc, color) in enumerate(phases):
        py = 200 + i * 80
        draw.rounded_rectangle([1100, py, 1750, py+60], radius=8, fill=(25, 40, 30), outline=color)
        draw.text((1120, py+12), f"{phase}: {desc}", font=get_font(24, True), fill=color)

    # Security experience
    draw.rounded_rectangle([1100, 500, 1750, 730], radius=12, fill=(25, 25, 50), outline=ACCENT)
    draw.text((1120, 515), "Security Experience", font=get_font(26, True), fill=ACCENT)
    exp = [
        "50+ findings submitted",
        "Code4rena, Immunefi, Guardian",
        "Rex Engine: consensus AI audit",
        "Solomon Edge MCP: real AI stack",
    ]
    for i, line in enumerate(exp):
        draw.text((1140, 560 + i * 35), f"  {line}", font=get_font(20), fill=GRAY)

    # Bottom CTA
    draw.rounded_rectangle([300, 800, W-300, 870], radius=12, fill=(30, 50, 35), outline=GREEN)
    draw_centered(draw, "99% Gross Margins  |  Pay-Per-Use  |  Zero CAC via MCP Distribution", 820, get_font(26, True), GREEN)

    path = OUTPUT_DIR / "slide_05_traction.png"
    img.save(path)
    return path


def slide_closing():
    """Slide 6: Closing — CTA"""
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    gradient_bg(draw, W, H, (20, 10, 50), (10, 40, 60))

    # Shield icon bigger
    cx, cy = W//2, 250
    points = [(cx, cy-120), (cx+100, cy-60), (cx+100, cy+60), (cx, cy+120), (cx-100, cy+60), (cx-100, cy-60)]
    draw.polygon(points, fill=ACCENT, outline=ACCENT2)
    draw.polygon([(cx, cy-80), (cx+60, cy-35), (cx+60, cy+35), (cx, cy+80), (cx-60, cy+35), (cx-60, cy-35)], fill=BG_DARK)
    draw.rectangle([cx-18, cy-8, cx+18, cy+22], fill=ACCENT2)
    draw.arc([cx-15, cy-28, cx+15, cy+2], 0, 360, fill=ACCENT2, width=4)

    draw_centered(draw, '"Security that lives where you code,', 420, get_font(40, True), WHITE)
    draw_centered(draw, 'paid the way agents pay."', 475, get_font(40, True), ACCENT2)

    # Install command
    draw_code_box(draw, "$ npm install -g solanashield-mcp", 500, 570, 920, 90, get_font(28))

    draw_centered(draw, "Built for Solana.  Built for AI.  Built at Colosseum Frontier.", 720, get_font(30, True), GRAY)

    # Links
    draw_centered(draw, "npmjs.com/package/solanashield-mcp  |  github.com/ElromEvedElElyon", 820, get_font(22), ACCENT)
    draw_centered(draw, "PadraoBitcoin  |  standardbitcoin.io@gmail.com", 860, get_font(22), GRAY)

    path = OUTPUT_DIR / "slide_06_closing.png"
    img.save(path)
    return path


def build_video(slides, output="pitch_video.mp4"):
    """Assemble slides into 3-minute video with transitions."""
    # Duration per slide (total ~180s = 3 min)
    durations = [15, 30, 45, 30, 30, 30]  # seconds each = 180s total

    clips = []
    for slide_path, duration in zip(slides, durations):
        clip = ImageClip(str(slide_path)).with_duration(duration)
        clips.append(clip)

    final = concatenate_videoclips(clips, method="compose")

    out_path = str(Path(__file__).parent / output)
    print(f"Rendering video to {out_path}...")
    print(f"Total duration: {sum(durations)}s ({sum(durations)//60}m{sum(durations)%60}s)")

    final.write_videofile(
        out_path,
        fps=24,
        codec="libx264",
        audio=False,
        preset="ultrafast",
        threads=2,
    )
    print(f"Video saved: {out_path}")
    return out_path


if __name__ == "__main__":
    print("=== SolanaShield Pitch Video Generator ===\n")

    print("Generating slides...")
    slides = [
        slide_title(),
        slide_problem(),
        slide_solution(),
        slide_architecture(),
        slide_traction(),
        slide_closing(),
    ]

    for s in slides:
        print(f"  Created: {s}")

    print(f"\n6 slides generated in {OUTPUT_DIR}/")

    if "--slides-only" not in sys.argv:
        print("\nBuilding video...")
        try:
            video_path = build_video(slides)
            print(f"\nDONE! Video: {video_path}")
            print("Duration: 3 minutes (180 seconds)")
            print("\nNext: Record narration over slides using the script from COLOSSEUM_PITCH.md")
        except Exception as e:
            print(f"\nVideo assembly failed: {e}")
            print("Slides are ready — use any video editor to assemble them.")
            print("Or install ffmpeg: sudo apt install ffmpeg")
    else:
        print("\nSlides-only mode. Run without --slides-only to build video.")

#!/usr/bin/env python3
"""Regenerate src/banner_art.rs from the mascot source image.

The installer and `kunato banner` embed the mascot as a compact RGB hex
string plus a monochrome ASCII fallback. This script decodes the PNG with the
standard library only, composites it over the banner background, downscales it
with an area filter, and writes the generated Rust module.

Usage:
    python3 scripts/render-banner.py [SOURCE] [OUTPUT]
"""

import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "kunato-chan-200x200.png"
OUTPUT = ROOT / "src/banner_art.rs"

WIDTH = 36
HEIGHT = 18
BACKGROUND = (23, 19, 20)
ASCII_RAMP = ".,:;+=xX$@"
HEX_PER_LINE = 96


def read_png(path):
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"{path}: not a PNG file")
    pos = 8
    idat = bytearray()
    width = height = depth = color_type = interlace = None
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        kind = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            width, height, depth, color_type, _, _, interlace = struct.unpack(
                ">IIBBBBB", chunk
            )
        elif kind == b"IDAT":
            idat += chunk
        elif kind == b"IEND":
            break
    if depth != 8 or color_type not in (2, 6) or interlace != 0:
        raise SystemExit(f"{path}: need an 8-bit, non-interlaced RGB/RGBA PNG")
    channels = 4 if color_type == 6 else 3
    stride = width * channels
    raw = zlib.decompress(bytes(idat))
    rows = []
    previous = bytearray(stride)
    pos = 0
    for _ in range(height):
        filter_type = raw[pos]
        pos += 1
        row = bytearray(raw[pos : pos + stride])
        pos += stride
        for index in range(stride):
            left = row[index - channels] if index >= channels else 0
            up = previous[index]
            up_left = previous[index - channels] if index >= channels else 0
            if filter_type == 1:
                row[index] = (row[index] + left) & 0xFF
            elif filter_type == 2:
                row[index] = (row[index] + up) & 0xFF
            elif filter_type == 3:
                row[index] = (row[index] + ((left + up) >> 1)) & 0xFF
            elif filter_type == 4:
                estimate = left + up - up_left
                pa = abs(estimate - left)
                pb = abs(estimate - up)
                pc = abs(estimate - up_left)
                predictor = (
                    left if pa <= pb and pa <= pc else (up if pb <= pc else up_left)
                )
                row[index] = (row[index] + predictor) & 0xFF
            elif filter_type != 0:
                raise SystemExit(f"{path}: unsupported PNG filter {filter_type}")
        rows.append(row)
        previous = row
    pixels = []
    for row in rows:
        for x in range(width):
            offset = x * channels
            if channels == 4:
                pixels.append(tuple(row[offset : offset + 4]))
            else:
                pixels.append((row[offset], row[offset + 1], row[offset + 2], 255))
    return width, height, pixels


def crop(pixels, width, height):
    left, top, right, bottom = width, height, -1, -1
    for y in range(height):
        for x in range(width):
            if pixels[y * width + x][3] > 8:
                left = min(left, x)
                top = min(top, y)
                right = max(right, x)
                bottom = max(bottom, y)
    if right < 0:
        raise SystemExit("the image is fully transparent")
    padding = 2
    left = max(0, left - padding)
    top = max(0, top - padding)
    right = min(width - 1, right + padding)
    bottom = min(height - 1, bottom + padding)
    cropped = []
    for y in range(top, bottom + 1):
        for x in range(left, right + 1):
            cropped.append(pixels[y * width + x])
    return right - left + 1, bottom - top + 1, cropped


def to_linear(value):
    value /= 255.0
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def to_srgb(value):
    value = max(0.0, min(1.0, value))
    value = value * 12.92 if value <= 0.0031308 else 1.055 * value ** (1 / 2.4) - 0.055
    return int(round(value * 255))


def resize(source, width, height, out_width, out_height, channels):
    """Area-average a list of channel tuples, with exact fractional coverage."""
    x_spans = []
    for out_x in range(out_width):
        start = out_x * width / out_width
        end = (out_x + 1) * width / out_width
        x_spans.append((start, end))
    y_spans = []
    for out_y in range(out_height):
        start = out_y * height / out_height
        end = (out_y + 1) * height / out_height
        y_spans.append((start, end))
    result = []
    for y0, y1 in y_spans:
        y_start = int(y0)
        y_end = min(height, int(y1) + 1)
        for x0, x1 in x_spans:
            x_start = int(x0)
            x_end = min(width, int(x1) + 1)
            totals = [0.0] * channels
            total_weight = 0.0
            for y in range(y_start, y_end):
                wy = min(y1, y + 1) - max(y0, y)
                if wy <= 0:
                    continue
                for x in range(x_start, x_end):
                    wx = min(x1, x + 1) - max(x0, x)
                    if wx <= 0:
                        continue
                    weight = wx * wy
                    pixel = source[y * width + x]
                    for channel in range(channels):
                        totals[channel] += pixel[channel] * weight
                    total_weight += weight
            result.append(tuple(total / total_weight for total in totals))
    return result


def build(source_path):
    width, height, pixels = read_png(source_path)
    width, height, pixels = crop(pixels, width, height)

    linear = []
    alpha = []
    for red, green, blue, a in pixels:
        opacity = a / 255.0
        alpha.append(opacity)
        linear.append(
            (
                to_linear(red) * opacity + to_linear(BACKGROUND[0]) * (1 - opacity),
                to_linear(green) * opacity + to_linear(BACKGROUND[1]) * (1 - opacity),
                to_linear(blue) * opacity + to_linear(BACKGROUND[2]) * (1 - opacity),
            )
        )
    color_pixels = resize(linear, width, height, WIDTH, HEIGHT * 2, 3)
    rgb = "".join(
        "".join(f"{to_srgb(channel):02x}" for channel in pixel)
        for pixel in color_pixels
    )
    if len(rgb) != WIDTH * HEIGHT * 2 * 6:
        raise SystemExit("internal error: wrong RGB payload size")

    shades = []
    for red, green, blue, _ in pixels:
        shades.append((0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255.0)
    alpha_cells = resize([(value,) for value in alpha], width, height, WIDTH, HEIGHT, 1)
    shade_cells = resize([(value,) for value in shades], width, height, WIDTH, HEIGHT, 1)
    lines = []
    for y in range(HEIGHT):
        line = []
        for x in range(WIDTH):
            if alpha_cells[y * WIDTH + x][0] < 0.12:
                line.append(" ")
                continue
            level = min(
                len(ASCII_RAMP) - 1,
                max(
                    0,
                    int(
                        round(
                            shade_cells[y * WIDTH + x][0] * (len(ASCII_RAMP) - 1)
                        )
                    ),
                ),
            )
            line.append(ASCII_RAMP[level])
        lines.append("".join(line).rstrip())

    header = (
        "// Generated by scripts/render-banner.py from kunato-chan-200x200.png.\n"
        "// Do not edit by hand; rerun the script after changing the source image.\n\n"
    )
    parts = [header]
    parts.append(f"pub const MASCOT_WIDTH: usize = {WIDTH};\n")
    parts.append(f"pub const MASCOT_HEIGHT: usize = {HEIGHT};\n\n")
    parts.append("pub const MASCOT_RGB: &str = concat!(\n")
    for start in range(0, len(rgb), HEX_PER_LINE):
        parts.append(f'    "{rgb[start:start + HEX_PER_LINE]}",\n')
    parts.append(");\n\n")
    parts.append("pub const MASCOT_ASCII: [&str; MASCOT_HEIGHT] = [\n")
    for line in lines:
        parts.append(f'    "{line}",\n')
    parts.append("];\n")
    return "".join(parts)


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else SOURCE
    output = sys.argv[2] if len(sys.argv) > 2 else OUTPUT
    text = build(source)
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"wrote {output} ({len(text)} bytes)")


if __name__ == "__main__":
    main()

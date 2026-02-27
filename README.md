# vulnsig-py

Render CVSS vulnerability vectors as expressive SVG glyphs. Each glyph encodes all base metrics visually with shape, color, rings, and texture, so vulnerabilities are recognizable at a glance.

Supports CVSS 4.0, 3.1, and 3.0.

## Install

```bash
pip install vulnsig
```

## Usage

```python
from vulnsig import render_glyph

svg = render_glyph("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")

# override the score (e.g. if you already have it)
svg = render_glyph("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", score=10.0)

# control rendered size in pixels (default 120)
svg = render_glyph("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", size=64)
```

`render_glyph` returns an SVG string ready to embed in HTML or write to a file.

## Examples

### CVSS 4.0

| Glyph | Name | Vector | Score |
|:-----:|------|--------|------:|
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/log4shell.svg" width="80"> | Log4Shell | `AV:N AC:L AT:N PR:N UI:N VC:H VI:H VA:H SC:H SI:H SA:H` | 10.0 |
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/eternalblue.svg" width="80"> | EternalBlue | `AV:N AC:L AT:N PR:N UI:N VC:H VI:H VA:H SC:N SI:N SA:N` | 9.3 |
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/heartbleed.svg" width="80"> | Heartbleed | `AV:N AC:L AT:N PR:N UI:N VC:H VI:N VA:N SC:L SI:N SA:N` | 8.7 |
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/spectre.svg" width="80"> | Spectre | `AV:L AC:H AT:P PR:L UI:N VC:H VI:N VA:N SC:H SI:N SA:N` | 5.6 |
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/xss-stored.svg" width="80"> | XSS Stored | `AV:N AC:L AT:N PR:L UI:P VC:L VI:L VA:N SC:N SI:N SA:N` | 5.1 |
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/usb-physical.svg" width="80"> | USB Drop | `AV:P AC:L AT:N PR:N UI:N VC:H VI:H VA:H SC:N SI:N SA:N` | 7.3 |

### CVSS 3.x

| Glyph | Name | Vector | Score |
|:-----:|------|--------|------:|
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/log4shell-31.svg" width="80"> | Log4Shell | `AV:N AC:L PR:N UI:N S:C C:H I:H A:H` | 10.0 |
| <img src="https://raw.githubusercontent.com/vulnsig/vulnsig-py/main/assets/xss-reflected-31.svg" width="80"> | XSS Reflected | `AV:N AC:L PR:N UI:R S:C C:L I:L A:N` | 6.1 |

## Visual encoding

Each metric maps to a distinct visual channel:

| Metric | Channel |
|--------|---------|
| Score | Hue — yellow (low) → orange → dark red (high) |
| AV | Star points — N=8, A=6, L=4, P=3 |
| AC | Star pointiness — L=sharp, H=blunt |
| AT | Ring segmentation — N=solid, P=cut pattern |
| PR | Star outline — N=none, L=thin, H=thick |
| UI | Perimeter — N=spikes, P=bumps, A=clean |
| VC/VI/VA | Inner ring brightness per sector |
| SC/SI/SA | Outer ring band (split when any > 0) |

## Requirements

Python 3.10+

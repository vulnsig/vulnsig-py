import ctypes
import math

from .color import score_to_hue
from .geometry import arc_path, radial_cuts, ring_fill, star_path
from .parse import detect_cvss_version, get_severity, is_version3, parse_cvss
from .score import calculate_score

def render_glyph(vector: str, score: float | None = None, size: int = 120) -> str:
    metrics = parse_cvss(vector)
    version = detect_cvss_version(vector)

    # Score precedence: explicit → auto-calculate
    if score is None:
        score = calculate_score(vector)

    hue_result = score_to_hue(score)
    hue = hue_result["hue"]
    sat = hue_result["sat"]
    light = hue_result["light"]

    # Metric severities - handle CVSS 3.0, 3.1, and 4.0
    ac = get_severity(metrics, "AC")

    # For CVSS 3.0/3.1, AT doesn't exist, so always treat as solid (AT:N)
    at = 1.0 if is_version3(version) else get_severity(metrics, "AT")

    # For CVSS 3.0/3.1, use C/I/A instead of VC/VI/VA
    vc = get_severity(metrics, "C") if is_version3(version) else get_severity(metrics, "VC")
    vi = get_severity(metrics, "I") if is_version3(version) else get_severity(metrics, "VI")
    va = get_severity(metrics, "A") if is_version3(version) else get_severity(metrics, "VA")

    # For CVSS 3.0/3.1, if S:C (Changed), both bands mirror C/I/A. If S:U (Unchanged), no split.
    if is_version3(version):
        scope_changed = get_severity(metrics, "S") > 0.5  # S:C = 1.0, S:U = 0.0
        if scope_changed:
            # Split band: both bands mirror C/I/A
            sc, si, sa = vc, vi, va
        else:
            # No split
            sc = si = sa = 0.0
    else:
        # CVSS 4.0: use SC/SI/SA directly
        sc = get_severity(metrics, "SC")
        si = get_severity(metrics, "SI")
        sa = get_severity(metrics, "SA")

    has_any_sub = sc > 0 or si > 0 or sa > 0
    at_present = at < 0.5

    cx = cy = 60.0
    petal_count = {"N": 8, "A": 6, "L": 4, "P": 3}.get(metrics.get("AV", ""), 8)  # type: ignore[call-overload]

    # Geometry constants
    ring_width = 4.375
    ring_gap = 1.5
    outer_r = 44.0
    hue_ring_r = outer_r + ring_gap + ring_width / 2

    sub_inner_r = outer_r - ring_width
    vuln_outer_r = sub_inner_r - ring_gap
    vuln_inner_r = vuln_outer_r - ring_width
    inner_r = vuln_inner_r

    gap_deg = 3.0
    cut_gap_deg = 4.0
    cut_width_deg = 3.0

    star_outer_r = inner_r - 2
    star_inner_r = star_outer_r * (0.55 - ac * 0.35)

    # PR stroke
    pr_raw = metrics.get("PR", "")  # type: ignore[call-overload]
    pr_stroke_width = 3.2 if pr_raw == "H" else (1.0 if pr_raw == "L" else 0.0)

    # UI spikes/bumps
    ui_raw = metrics.get("UI", "")  # type: ignore[call-overload]
    spike_base = hue_ring_r + ring_width / 2 - 0.5

    # Star fill — match the outer hue ring color
    sf_sat = sat
    sf_light = 52 * light
    sf_alpha = 0.85

    bg_color = f"hsl({hue}, 4%, 5%)"

    # Deterministic gradient ID from vector hash
    grad_id = "sg-" + _simple_hash(vector)

    # Sectors
    sectors = [
        {"key": "C", "s": -150 + gap_deg / 2, "e": -30 - gap_deg / 2, "vuln": vc, "sub": sc},
        {"key": "I", "s": -30 + gap_deg / 2, "e": 90 - gap_deg / 2, "vuln": vi, "sub": si},
        {"key": "A", "s": 90 + gap_deg / 2, "e": 210 - gap_deg / 2, "vuln": va, "sub": sa},
    ]

    parts: list[str] = []

    # Defs
    parts.append(f'<defs><radialGradient id="{grad_id}" cx="50%" cy="50%" r="50%">')
    parts.append(
        f'<stop offset="0%" stop-color="hsla({hue}, {sf_sat * 1.1}%, {sf_light + 6}%, {min(1.0, sf_alpha + 0.1)})"/>'
    )
    parts.append(f'<stop offset="100%" stop-color="hsla({hue}, {sf_sat}%, {sf_light}%, {sf_alpha})"/>')
    parts.append("</radialGradient></defs>")

    # Z-order 1: UI:N Spikes
    if ui_raw == "N":
        for i in range(petal_count):
            a = (math.pi * 2 * i) / petal_count - math.pi / 2
            x1 = cx + math.cos(a) * spike_base
            y1 = cy + math.sin(a) * spike_base
            x2 = cx + math.cos(a) * (spike_base + 3.4)
            y2 = cy + math.sin(a) * (spike_base + 3.4)
            parts.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="hsl({hue}, {sat}%, {52 * light}%)" stroke-width="3.0" stroke-linecap="round"/>'
            )

    # Z-order 2: UI:P Bumps
    if ui_raw == "P":
        bump_r = 4.6
        for i in range(petal_count):
            a = (math.pi * 2 * i) / petal_count - math.pi / 2
            bx = cx + math.cos(a) * spike_base
            by = cy + math.sin(a) * spike_base
            perp_l = a - math.pi / 2
            perp_r = a + math.pi / 2
            x1 = bx + math.cos(perp_l) * bump_r
            y1 = by + math.sin(perp_l) * bump_r
            x2 = bx + math.cos(perp_r) * bump_r
            y2 = by + math.sin(perp_r) * bump_r
            parts.append(
                f'<path d="M{x1},{y1} A{bump_r},{bump_r} 0 0,1 {x2},{y2} Z" '
                f'fill="hsl({hue}, {sat}%, {52 * light}%)"/>'
            )

    # Z-order 3: Background circle
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="{inner_r}" fill="{bg_color}"/>')

    # Z-order 4: Star fill
    star_d = star_path(cx, cy, petal_count, star_outer_r, star_inner_r)
    parts.append(f'<path d="{star_d}" fill="url(#{grad_id})" stroke="none"/>')

    # Z-order 5: Star stroke (PR:N = no stroke)
    if pr_stroke_width > 0:
        parts.append(
            f'<path d="{star_d}" fill="none" stroke="hsl({hue}, {sat}%, {72 * light}%)" '
            f'stroke-width="{pr_stroke_width}" stroke-linejoin="round"/>'
        )

    # Z-order 6 & 7: CIA ring sectors
    for sec in sectors:
        # Vuln band (inner)
        vuln_band_outer = vuln_outer_r if has_any_sub else outer_r
        parts.append(
            f'<path d="{arc_path(cx, cy, vuln_inner_r, vuln_band_outer, sec["s"], sec["e"])}" '
            f'fill="{ring_fill(sec["vuln"], hue, sat, light)}"/>'
        )

        # Sub band (outer) — only when split
        if has_any_sub:
            parts.append(
                f'<path d="{arc_path(cx, cy, sub_inner_r, outer_r, sec["s"], sec["e"])}" '
                f'fill="{ring_fill(sec["sub"], hue, sat, light)}"/>'
            )

    # Z-order 8: AT:P radial cuts
    if at_present:
        for sec in sectors:
            cuts = radial_cuts(sec["s"], sec["e"], cut_width_deg, cut_gap_deg)
            for cut in cuts:
                parts.append(
                    f'<path d="{arc_path(cx, cy, vuln_inner_r - 0.5, outer_r + 0.5, cut["startDeg"], cut["endDeg"])}" '
                    f'fill="{bg_color}"/>'
                )

    # Z-order 9: Outer hue ring
    parts.append(
        f'<circle cx="{cx}" cy="{cy}" r="{hue_ring_r}" fill="none" '
        f'stroke="hsl({hue}, {sat}%, {52 * light}%)" stroke-width="{ring_width}"/>'
    )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 120 120" style="overflow:visible">{"".join(parts)}</svg>'
    )


def _simple_hash(s: str) -> str:
    h = 0
    for ch in s:
        h = ctypes.c_int32((h << 5) - h + ord(ch)).value
    return _to_base36(abs(h))


def _to_base36(n: int) -> str:
    if n == 0:
        return "0"
    digits: list[str] = []
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    while n:
        digits.append(alphabet[n % 36])
        n //= 36
    return "".join(reversed(digits))

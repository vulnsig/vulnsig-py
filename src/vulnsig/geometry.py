import math
from typing import NamedTuple

_DEG2RAD = math.pi / 180


class Cut(NamedTuple):
    start_deg: float
    end_deg: float


def arc_path(
    cx: float,
    cy: float,
    inner_r: float,
    outer_r: float,
    start_deg: float,
    end_deg: float,
) -> str:
    s = start_deg * _DEG2RAD
    e = end_deg * _DEG2RAD
    la = 1 if (end_deg - start_deg) > 180 else 0
    osx = cx + math.cos(s) * outer_r
    osy = cy + math.sin(s) * outer_r
    oex = cx + math.cos(e) * outer_r
    oey = cy + math.sin(e) * outer_r
    iex = cx + math.cos(e) * inner_r
    iey = cy + math.sin(e) * inner_r
    isx = cx + math.cos(s) * inner_r
    isy = cy + math.sin(s) * inner_r
    return (
        f'M{osx},{osy} A{outer_r},{outer_r} 0 {la},1 {oex},{oey} '
        f'L{iex},{iey} A{inner_r},{inner_r} 0 {la},0 {isx},{isy} Z'
    )


def star_path(
    cx: float,
    cy: float,
    points: int,
    outer_r: float,
    inner_r: float,
) -> str:
    d = ''
    for i in range(points):
        oa = (math.pi * 2 * i) / points - math.pi / 2
        ia = (math.pi * 2 * (i + 0.5)) / points - math.pi / 2
        ox = cx + math.cos(oa) * outer_r
        oy = cy + math.sin(oa) * outer_r
        ix = cx + math.cos(ia) * inner_r
        iy = cy + math.sin(ia) * inner_r
        if i == 0:
            d += f'M{ox},{oy}'
        else:
            d += f'L{ox},{oy}'
        d += f'L{ix},{iy}'
    return d + 'Z'


def radial_cuts(
    start_deg: float,
    end_deg: float,
    cut_width: float,
    gap_deg: float,
) -> list[Cut]:
    cuts: list[Cut] = []
    sector_span = end_deg - start_deg
    step = cut_width + gap_deg
    # Number of visible segments = num_cuts + 1, each gap_deg wide.
    # Total = num_cuts * cut_width + (num_cuts + 1) * gap_deg = sector_span
    # Solve: num_cuts = floor((sector_span - gap_deg) / step)
    num_cuts = int((sector_span - gap_deg) / step)
    pattern_span = num_cuts * cut_width + (num_cuts + 1) * gap_deg
    offset = (sector_span - pattern_span) / 2
    for i in range(num_cuts):
        cut_start = start_deg + offset + (i + 1) * gap_deg + i * cut_width
        cuts.append(Cut(start_deg=cut_start, end_deg=cut_start + cut_width))
    return cuts


def ring_fill(magnitude: float, hue: float, sat: float, light: float = 1.0) -> str:
    if magnitude <= 0.01:
        return f'hsla({hue}, {sat * 0.1}%, {12 * light}%, 0.9)'
    if magnitude <= 0.5:
        return f'hsla({hue}, {sat * 0.5}%, {35 * light}%, 0.92)'
    return f'hsla({hue}, {sat * 0.9}%, {58 * light}%, 0.95)'

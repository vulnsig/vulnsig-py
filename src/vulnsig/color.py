from .types import HueResult


def score_to_hue(score: float) -> HueResult:
    w = max(0.0, min(10.0, score)) / 10.0

    # Light Yellow (low) → Orange (mid) → Dark Red (high)
    #   0 = light yellow  hsl(55, 95%, 55%)
    #   5 = orange         hsl(25, 95%, 53%)
    #  10 = dark red       hsl(0, 80%, 28%)
    if w <= 0.5:
        # light yellow → orange: hue 55 → 25
        hue = 55 - (w / 0.5) * 30
    else:
        # orange → dark red: hue 25 → 0
        hue = 25 - ((w - 0.5) / 0.5) * 25

    sat = 85 + (1 - w) * 10  # 95% at low → 85% at high

    # Lightness multiplier: asymmetric — subtle brightening for low scores,
    # aggressive darkening for high scores (8-10 distinguishability)
    #   score 0: 1.15, score 5: 1.0, score 10: 0.55
    if w <= 0.5:
        light = 1.0 + (0.5 - w) * 0.3   # low end:  1.0 → 1.15
    else:
        light = 1.0 - (w - 0.5) * 0.9   # high end: 1.0 → 0.55

    return HueResult(hue=hue, sat=sat, light=light)

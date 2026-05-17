from cvss import CVSS2, CVSS3, CVSS4  # type: ignore

from .parse import detect_cvss_version, normalize_v2_vector


def calculate_score(vector: str) -> float:
    version = detect_cvss_version(vector)
    if version in ('3.0', '3.1'):
        c3 = CVSS3(vector)
        return float(c3.base_score)
    if version == '2.0':
        # The cvss library doesn't tolerate the optional `CVSS:2.0/` prefix or
        # outer parens, so normalize first.
        c2 = CVSS2(normalize_v2_vector(vector))
        # Prefer the most specific score available: env > temporal > base,
        # parallel to ae-cvss-calculator's `overall`.
        if c2.environmental_score is not None:
            return float(c2.environmental_score)
        if c2.temporal_score is not None:
            return float(c2.temporal_score)
        return float(c2.base_score)
    # CVSS 4.0 (validated by detect_cvss_version)
    c4 = CVSS4(vector)
    return float(c4.base_score)

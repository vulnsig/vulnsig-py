from cvss import CVSS3, CVSS4  # type: ignore

from .parse import detect_cvss_version


def calculate_score(vector: str) -> float:
    version = detect_cvss_version(vector)
    if version in ('3.0', '3.1'):
        c = CVSS3(vector)
        return float(c.base_score)
    # CVSS 4.0 (validated by detect_cvss_version)
    c = CVSS4(vector)
    return float(c.base_score)

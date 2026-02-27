from .types import MetricKey, ParsedMetrics

METRIC_DEFS: dict[MetricKey, dict[str, float]] = {
    'AV': {'N': 1.0, 'A': 0.7, 'L': 0.4, 'P': 0.15},
    'AC': {'L': 1.0, 'H': 0.4},
    'AT': {'N': 1.0, 'P': 0.4},
    'PR': {'N': 1.0, 'L': 0.6, 'H': 0.2},
    'UI': {'N': 1.0, 'P': 0.6, 'A': 0.2, 'R': 0.2},  # R for CVSS 3.0/3.1
    'VC': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'VI': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'VA': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'SC': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'SI': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'SA': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    # CVSS 3.0/3.1 metrics (C/I/A without V prefix, S for scope)
    'C': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'I': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'A': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'S': {'C': 1.0, 'U': 0.0},  # Scope: Changed or Unchanged
}


def parse_cvss(vector: str) -> ParsedMetrics:
    m: dict[str, str] = {}
    for part in vector.split('/'):
        if ':' in part:
            key, val = part.split(':', 1)
            if key in METRIC_DEFS:
                m[key] = val
    return m  # type: ignore[return-value]


def detect_cvss_version(vector: str) -> str:
    if vector.startswith('CVSS:3.1/'):
        return '3.1'
    elif vector.startswith('CVSS:3.0/'):
        return '3.0'
    elif vector.startswith('CVSS:4.0/'):
        return '4.0'
    raise ValueError(
        "Unsupported CVSS version. Vector must start with 'CVSS:3.0/', 'CVSS:3.1/', or 'CVSS:4.0/'"
    )


def is_version3(version: str) -> bool:
    return version in ('3.0', '3.1')


def get_severity(metrics: ParsedMetrics, key: MetricKey) -> float:
    return METRIC_DEFS[key][metrics[key]]

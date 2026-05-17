from .types import MetricKey, ParsedMetrics

METRIC_DEFS: dict[MetricKey, dict[str, float]] = {
    'AV': {'N': 1.0, 'A': 0.7, 'L': 0.4, 'P': 0.15},
    'AC': {'L': 1.0, 'M': 0.7, 'H': 0.4},  # M for CVSS 2.0
    'AT': {'N': 1.0, 'P': 0.4},
    'PR': {'N': 1.0, 'L': 0.6, 'H': 0.2},
    'UI': {'N': 1.0, 'P': 0.6, 'A': 0.2, 'R': 0.2},  # R for CVSS 3.0/3.1
    # CVSS 2.0 Authentication — mirrors PR shape so the stroke-width
    # branch in render.py can reuse the same function.
    'Au': {'N': 1.0, 'S': 0.6, 'M': 0.2},
    'VC': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'VI': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'VA': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'SC': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'SI': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'SA': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    # CVSS 3.x C/I/A use H/L/N; CVSS 2.0 uses C/P/N — both resolve here.
    'C': {'H': 1.0, 'C': 1.0, 'L': 0.5, 'P': 0.5, 'N': 0.0},
    'I': {'H': 1.0, 'C': 1.0, 'L': 0.5, 'P': 0.5, 'N': 0.0},
    'A': {'H': 1.0, 'C': 1.0, 'L': 0.5, 'P': 0.5, 'N': 0.0},
    'S': {'C': 1.0, 'U': 0.0},  # Scope: Changed or Unchanged
    # Exploit Maturity — superset of CVSS 4.0 (A/P/U/X) and CVSS 2.0 (U/POC/F/H/ND).
    'E': {
        'A': 1.0,
        'H': 1.0,
        'F': 0.8,
        'P': 0.6,
        'POC': 0.6,
        'U': 0.2,
        'X': 0.0,
        'ND': 0.0,
    },
    # CVSS 2.0 temporal / environmental — included so parse_cvss retains them.
    'RL': {'OF': 0.0, 'TF': 0.4, 'W': 0.7, 'U': 1.0, 'ND': 0.0},
    'RC': {'UC': 0.3, 'UR': 0.6, 'C': 1.0, 'ND': 0.0},
    'CDP': {'N': 0.0, 'L': 0.2, 'LM': 0.4, 'MH': 0.6, 'H': 1.0, 'ND': 0.0},
    'TD': {'N': 0.0, 'L': 0.3, 'M': 0.6, 'H': 1.0, 'ND': 0.0},
    'CR': {'L': 0.4, 'M': 0.7, 'H': 1.0, 'ND': 0.0},
    'IR': {'L': 0.4, 'M': 0.7, 'H': 1.0, 'ND': 0.0},
    'AR': {'L': 0.4, 'M': 0.7, 'H': 1.0, 'ND': 0.0},
}


def normalize_v2_vector(vector: str) -> str:
    """Strip optional `CVSS:2.0/` prefix, surrounding parens, and leading/trailing slashes.

    CVSS 2.0 is commonly written bare (no prefix), occasionally in parens,
    and sometimes with a non-spec ``CVSS:2.0/`` prefix.
    """
    s = vector.strip()
    if s.startswith('('):
        s = s[1:]
    if s.endswith(')'):
        s = s[:-1]
    if s.startswith('CVSS:2.0/'):
        s = s[len('CVSS:2.0/') :]
    return s.strip('/')


def parse_cvss(vector: str) -> ParsedMetrics:
    try:
        version = detect_cvss_version(vector)
    except ValueError:
        version = None
    body = normalize_v2_vector(vector) if version == '2.0' else vector
    m: dict[str, str] = {}
    for part in body.split('/'):
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
    elif vector.startswith('CVSS:2.0/'):
        return '2.0'
    elif not vector.startswith('CVSS:') and _looks_like_cvss2(vector):
        return '2.0'
    raise ValueError(
        "Unsupported CVSS version. Vector must start with 'CVSS:2.0/', "
        "'CVSS:3.0/', 'CVSS:3.1/', or 'CVSS:4.0/', or be a bare CVSS 2.0 vector."
    )


def _looks_like_cvss2(vector: str) -> bool:
    """CVSS 2.0 base vectors always include AV, AC, Au, C, I, A.

    Require the v2-distinctive ``Au`` token plus ``AV``/``AC`` so random
    strings still raise.
    """
    body = normalize_v2_vector(vector)
    tokens: set[str] = set()
    for part in body.split('/'):
        if ':' in part:
            tokens.add(part.split(':', 1)[0])
    return {'Au', 'AV', 'AC'}.issubset(tokens)


def is_version3(version: str) -> bool:
    return version in ('3.0', '3.1')


def is_version2(version: str) -> bool:
    return version == '2.0'


def get_severity(metrics: ParsedMetrics, key: MetricKey) -> float:
    return METRIC_DEFS[key][metrics[key]]

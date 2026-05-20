from typing import Literal, TypedDict

MetricKey = Literal[
    'AV',
    'AC',
    'AT',
    'PR',
    'UI',
    'Au',
    'VC',
    'VI',
    'VA',
    'SC',
    'SI',
    'SA',
    'C',
    'I',
    'A',
    'S',
    'E',
    'RL',
    'RC',
    'CDP',
    'TD',
    'CR',
    'IR',
    'AR',
]


class ParsedMetrics(TypedDict, total=False):
    # Base — shared across versions (with value-set differences)
    AV: Literal['N', 'A', 'L', 'P']
    AC: Literal['L', 'M', 'H']  # M only in CVSS 2.0
    PR: Literal['N', 'L', 'H']  # CVSS 3.x / 4.0
    UI: Literal['N', 'P', 'A', 'R']  # R for CVSS 3.x; absent in CVSS 2.0
    # CVSS 4.0 only
    AT: Literal['N', 'P']
    VC: Literal['H', 'L', 'N']
    VI: Literal['H', 'L', 'N']
    VA: Literal['H', 'L', 'N']
    SC: Literal['H', 'L', 'N']
    SI: Literal['H', 'L', 'N']
    SA: Literal['H', 'L', 'N']
    # CVSS 3.x C/I/A use H/L/N; CVSS 2.0 uses C/P/N
    C: Literal['H', 'L', 'N', 'C', 'P']
    I: Literal['H', 'L', 'N', 'C', 'P']  # noqa: E741
    A: Literal['H', 'L', 'N', 'C', 'P']
    S: Literal['C', 'U']  # Scope (CVSS 3.x)
    # CVSS 2.0 Authentication
    Au: Literal['N', 'S', 'M']
    # Exploit Maturity — CVSS 4.0 uses A/P/U/X; CVSS 2.0 uses U/POC/F/H/ND
    E: Literal['A', 'P', 'U', 'X', 'POC', 'F', 'H', 'ND']
    # CVSS 2.0 temporal
    RL: Literal['OF', 'TF', 'W', 'U', 'ND']
    RC: Literal['UC', 'UR', 'C', 'ND']
    # CVSS 2.0 environmental
    CDP: Literal['N', 'L', 'LM', 'MH', 'H', 'ND']
    TD: Literal['N', 'L', 'M', 'H', 'ND']
    CR: Literal['L', 'M', 'H', 'ND']
    IR: Literal['L', 'M', 'H', 'ND']
    AR: Literal['L', 'M', 'H', 'ND']


class HueResult(TypedDict):
    hue: float
    sat: float
    light: float  # multiplier: >1 lighter (low scores), <1 darker (high scores)

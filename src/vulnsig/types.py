from typing import Literal, TypedDict

MetricKey = Literal[
    'AV',
    'AC',
    'AT',
    'PR',
    'UI',
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
]


class ParsedMetrics(TypedDict, total=False):
    # CVSS 4.0 + 3.x shared
    AV: Literal['N', 'A', 'L', 'P']
    AC: Literal['L', 'H']
    PR: Literal['N', 'L', 'H']
    UI: Literal['N', 'P', 'A', 'R']  # R for CVSS 3.0/3.1
    # CVSS 4.0 only
    AT: Literal['N', 'P']
    VC: Literal['H', 'L', 'N']
    VI: Literal['H', 'L', 'N']
    VA: Literal['H', 'L', 'N']
    SC: Literal['H', 'L', 'N']
    SI: Literal['H', 'L', 'N']
    SA: Literal['H', 'L', 'N']
    # CVSS 3.x only
    C: Literal['H', 'L', 'N']
    I: Literal['H', 'L', 'N']  # noqa: E741
    A: Literal['H', 'L', 'N']
    S: Literal['C', 'U']  # Scope: Changed or Unchanged


class HueResult(TypedDict):
    hue: float
    sat: float
    light: float  # multiplier: >1 lighter (low scores), <1 darker (high scores)

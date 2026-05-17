import json
from pathlib import Path

import pytest

from vulnsig import render_glyph
from vulnsig.color import score_to_hue
from vulnsig.parse import (
    detect_cvss_version,
    is_version2,
    is_version3,
    parse_cvss,
)
from vulnsig.score import calculate_score

LOG4SHELL = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'

# CVSS 4.0 vectors with E (Exploit Maturity) threat metric
LOG4SHELL_E_A = LOG4SHELL + '/E:A'
LOG4SHELL_E_P = LOG4SHELL + '/E:P'
LOG4SHELL_E_U = LOG4SHELL + '/E:U'
LOG4SHELL_E_X = LOG4SHELL + '/E:X'

# CVSS 3.1 test vectors
CVSS31_LOG4SHELL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
CVSS31_HEARTBLEED = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
CVSS31_DIRTY_COW = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'
CVSS31_XSS = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'

# CVSS 3.0 test vectors (same format as 3.1)
CVSS30_LOG4SHELL = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
CVSS30_HEARTBLEED = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
CVSS30_XSS = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'

# CVSS 2.0 test vectors (bare, no prefix)
CVSS2_HEARTBLEED = 'AV:N/AC:L/Au:N/C:P/I:N/A:N'
CVSS2_WORST = 'AV:N/AC:L/Au:N/C:C/I:C/A:C'
CVSS2_LOCAL_LOW = 'AV:L/AC:H/Au:M/C:P/I:N/A:N'
CVSS2_PREFIXED = 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P'
CVSS2_WITH_E_H = 'AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:OF/RC:C'
CVSS2_AC_M = 'AV:N/AC:M/Au:S/C:P/I:P/A:N'
CVSS2_PARENS = '(AV:N/AC:M/Au:N/C:N/I:P/A:N)'
CVSS2_AU_M = 'AV:N/AC:L/Au:M/C:C/I:C/A:C'

_TEST_VECTORS_PATH = Path(__file__).parent.parent / 'spec' / 'test-vectors.json'
with _TEST_VECTORS_PATH.open() as _f:
    TEST_VECTORS = json.load(_f)


# ---------------------------------------------------------------------------
# parse_cvss
# ---------------------------------------------------------------------------


class TestParseCVSS:
    def test_parses_full_vector(self):
        m = parse_cvss(LOG4SHELL)
        assert m['AV'] == 'N'
        assert m['AC'] == 'L'
        assert m['SC'] == 'H'

    def test_parses_e_metric(self):
        assert parse_cvss(LOG4SHELL_E_A)['E'] == 'A'
        assert parse_cvss(LOG4SHELL_E_P)['E'] == 'P'
        assert parse_cvss(LOG4SHELL_E_U)['E'] == 'U'
        assert parse_cvss(LOG4SHELL_E_X)['E'] == 'X'

    def test_handles_missing_optional_metrics(self):
        m = parse_cvss('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')
        assert m['AV'] == 'N'
        assert m.get('SC') is None

    def test_parses_cvss31_vector(self):
        m = parse_cvss(CVSS31_LOG4SHELL)
        assert m['AV'] == 'N'
        assert m['AC'] == 'L'
        assert m['C'] == 'H'
        assert m['I'] == 'H'
        assert m['A'] == 'H'
        assert m['S'] == 'C'

    def test_parses_cvss30_vector(self):
        m = parse_cvss(CVSS30_LOG4SHELL)
        assert m['AV'] == 'N'
        assert m['AC'] == 'L'
        assert m['C'] == 'H'
        assert m['I'] == 'H'
        assert m['A'] == 'H'
        assert m['S'] == 'C'


# ---------------------------------------------------------------------------
# detect_cvss_version
# ---------------------------------------------------------------------------


class TestDetectCVSSVersion:
    def test_detects_30(self):
        assert detect_cvss_version(CVSS30_LOG4SHELL) == '3.0'

    def test_detects_31(self):
        assert detect_cvss_version(CVSS31_LOG4SHELL) == '3.1'

    def test_detects_40(self):
        assert detect_cvss_version(LOG4SHELL) == '4.0'

    def test_detects_20_bare(self):
        assert detect_cvss_version(CVSS2_HEARTBLEED) == '2.0'

    def test_detects_20_prefixed(self):
        assert detect_cvss_version(CVSS2_PREFIXED) == '2.0'

    def test_detects_20_parens_wrapped(self):
        assert detect_cvss_version(CVSS2_PARENS) == '2.0'

    def test_raises_for_unsupported_prefix(self):
        with pytest.raises(ValueError, match='Unsupported CVSS version'):
            detect_cvss_version('CVSS:1.0/AV:N')

    def test_raises_for_bare_garbage(self):
        # No Au — doesn't look like a CVSS 2.0 base vector.
        with pytest.raises(ValueError, match='Unsupported CVSS version'):
            detect_cvss_version('foo:bar/baz:qux')


# ---------------------------------------------------------------------------
# is_version3
# ---------------------------------------------------------------------------


class TestIsVersion3:
    def test_true_for_30(self):
        assert is_version3('3.0') is True

    def test_true_for_31(self):
        assert is_version3('3.1') is True

    def test_false_for_40(self):
        assert is_version3('4.0') is False


# ---------------------------------------------------------------------------
# score_to_hue
# ---------------------------------------------------------------------------


class TestScoreToHue:
    def test_yellow_for_score_0(self):
        assert score_to_hue(0)['hue'] == 55

    def test_dark_red_for_score_10(self):
        assert score_to_hue(10)['hue'] == 0

    def test_hue_decreases_with_score(self):
        assert score_to_hue(0)['hue'] > score_to_hue(10)['hue']


# ---------------------------------------------------------------------------
# calculate_score
# ---------------------------------------------------------------------------


class TestCalculateScore:
    def test_log4shell_is_10(self):
        assert calculate_score(LOG4SHELL) == 10.0

    def test_invalid_vector_returns_5(self):
        with pytest.raises(ValueError):
            calculate_score('garbage')

    def test_cvss31_log4shell(self):
        assert calculate_score(CVSS31_LOG4SHELL) == 10.0

    def test_cvss31_heartbleed(self):
        assert calculate_score(CVSS31_HEARTBLEED) == 7.5

    def test_cvss31_dirty_cow(self):
        assert calculate_score(CVSS31_DIRTY_COW) == 7.1

    def test_cvss31_xss(self):
        assert calculate_score(CVSS31_XSS) == 6.1

    def test_cvss30_log4shell(self):
        assert calculate_score(CVSS30_LOG4SHELL) == 10.0

    def test_cvss30_heartbleed(self):
        assert calculate_score(CVSS30_HEARTBLEED) == 7.5

    def test_cvss30_xss(self):
        assert calculate_score(CVSS30_XSS) == 6.1


# ---------------------------------------------------------------------------
# render_glyph
# ---------------------------------------------------------------------------


class TestRenderGlyph:
    def test_returns_valid_svg(self):
        svg = render_glyph(LOG4SHELL, score=10)
        assert svg.startswith('<svg ')
        assert svg.endswith('</svg>')

    def test_respects_size_parameter(self):
        svg = render_glyph(LOG4SHELL, score=10, size=64)
        assert 'width="64"' in svg
        assert 'height="64"' in svg

    def test_renders_all_test_vectors(self):
        for tv in TEST_VECTORS:
            svg = render_glyph(tv['vector'], score=tv['score'])
            assert svg.startswith('<svg ')
            assert svg.endswith('</svg>')

    def test_renders_cvss31_vectors(self):
        for vector in [CVSS31_LOG4SHELL, CVSS31_HEARTBLEED, CVSS31_DIRTY_COW, CVSS31_XSS]:
            svg = render_glyph(vector)
            assert svg.startswith('<svg ')
            assert svg.endswith('</svg>')

    def test_cvss31_scope_changed_split_band(self):
        svg = render_glyph(CVSS31_LOG4SHELL)
        assert '<svg' in svg
        assert '</svg>' in svg

    def test_cvss31_scope_unchanged_no_split(self):
        svg = render_glyph(CVSS31_HEARTBLEED)
        assert '<svg' in svg
        assert '</svg>' in svg

    def test_cvss31_ui_r_clean_perimeter(self):
        svg = render_glyph(CVSS31_XSS)
        assert '<svg' in svg
        assert '</svg>' in svg

    def test_renders_cvss30_vectors(self):
        for vector in [CVSS30_LOG4SHELL, CVSS30_HEARTBLEED, CVSS30_XSS]:
            svg = render_glyph(vector)
            assert svg.startswith('<svg ')
            assert svg.endswith('</svg>')

    def test_cvss30_scope_changed_split_band(self):
        svg = render_glyph(CVSS30_LOG4SHELL)
        assert '<svg' in svg
        assert '</svg>' in svg

    def test_cvss30_scope_unchanged_no_split(self):
        svg = render_glyph(CVSS30_HEARTBLEED)
        assert '<svg' in svg
        assert '</svg>' in svg

    def test_e_a_renders_concentric_rings(self):
        import re

        svg = render_glyph(LOG4SHELL_E_A, score=10)
        assert re.search(r'<circle[^>]*stroke="hsla\(', svg)

    def test_e_p_renders_solid_circle(self):
        import re

        svg = render_glyph(LOG4SHELL_E_P, score=10)
        assert re.search(r'<circle[^>]*fill="hsla\(', svg)

    def test_e_u_renders_no_marker(self):
        import re

        svg = render_glyph(LOG4SHELL_E_U, score=10)
        assert not re.search(r'<circle[^>]*fill="hsla\(', svg)
        assert not re.search(r'<circle[^>]*stroke="hsla\(', svg)

    def test_e_x_renders_no_marker(self):
        import re

        svg = render_glyph(LOG4SHELL_E_X, score=10)
        assert not re.search(r'<circle[^>]*fill="hsla\(', svg)
        assert not re.search(r'<circle[^>]*stroke="hsla\(', svg)

    def test_e_marker_ignored_for_cvss3x(self):
        import re

        svg = render_glyph(CVSS31_LOG4SHELL)
        assert not re.search(r'<circle[^>]*fill="hsla\(', svg)
        assert not re.search(r'<circle[^>]*stroke="hsla\(', svg)


# ---------------------------------------------------------------------------
# CVSS 2.0
# ---------------------------------------------------------------------------


class TestIsVersion2:
    def test_true_for_20(self):
        assert is_version2('2.0') is True

    def test_false_for_other(self):
        assert is_version2('3.0') is False
        assert is_version2('3.1') is False
        assert is_version2('4.0') is False


class TestCVSS2:
    def test_parses_bare(self):
        m = parse_cvss(CVSS2_HEARTBLEED)
        assert m['AV'] == 'N'
        assert m['AC'] == 'L'
        assert m['Au'] == 'N'
        assert m['C'] == 'P'
        assert m['I'] == 'N'
        assert m['A'] == 'N'

    def test_parses_prefixed(self):
        m = parse_cvss(CVSS2_PREFIXED)
        assert m['Au'] == 'N'
        assert m['C'] == 'P'

    def test_parses_parens_wrapped(self):
        m = parse_cvss(CVSS2_PARENS)
        assert m['AV'] == 'N'
        assert m['AC'] == 'M'
        assert m['I'] == 'P'

    def test_parses_temporal(self):
        m = parse_cvss(CVSS2_WITH_E_H)
        assert m['E'] == 'H'
        assert m['RL'] == 'OF'
        assert m['RC'] == 'C'

    def test_parses_ac_m(self):
        m = parse_cvss(CVSS2_AC_M)
        assert m['AC'] == 'M'
        assert m['Au'] == 'S'

    def test_score_heartbleed(self):
        assert calculate_score(CVSS2_HEARTBLEED) == pytest.approx(5.0, abs=0.05)

    def test_score_worst(self):
        assert calculate_score(CVSS2_WORST) == pytest.approx(10.0, abs=0.05)

    def test_score_auth_required(self):
        assert calculate_score('AV:N/AC:L/Au:S/C:P/I:P/A:P') == pytest.approx(6.5, abs=0.05)

    def test_score_local_ac_m(self):
        assert calculate_score('AV:L/AC:M/Au:N/C:P/I:P/A:P') == pytest.approx(4.4, abs=0.05)

    def test_score_with_temporal_lowers(self):
        assert calculate_score(CVSS2_WITH_E_H) == pytest.approx(8.7, abs=0.05)

    def test_prefixed_score_matches_bare(self):
        bare = 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
        assert calculate_score(CVSS2_PREFIXED) == pytest.approx(calculate_score(bare), abs=0.05)

    def test_parens_score_matches_unwrapped(self):
        unwrapped = 'AV:N/AC:M/Au:N/C:N/I:P/A:N'
        assert calculate_score(CVSS2_PARENS) == pytest.approx(calculate_score(unwrapped), abs=0.05)

    def test_renders_bare(self):
        svg = render_glyph(CVSS2_HEARTBLEED)
        assert svg.startswith('<svg ')
        assert svg.endswith('</svg>')

    def test_renders_parens(self):
        svg = render_glyph(CVSS2_PARENS)
        assert svg.startswith('<svg ')

    def test_renders_ac_m(self):
        svg = render_glyph(CVSS2_AC_M)
        assert svg.startswith('<svg ')

    def test_au_m_produces_thick_stroke(self):
        svg = render_glyph(CVSS2_AU_M)
        assert 'stroke-width="3.5"' in svg

    def test_au_n_produces_no_stroke(self):
        svg = render_glyph(CVSS2_WORST)
        assert 'stroke-width="3.5"' not in svg
        assert 'stroke-width="1.5"' not in svg

    def test_e_h_renders_concentric_rings(self):
        import re

        svg = render_glyph(CVSS2_WITH_E_H)
        assert re.search(r'<circle[^>]*stroke="hsla\(', svg)

    def test_renders_local_low(self):
        svg = render_glyph(CVSS2_LOCAL_LOW)
        assert svg.startswith('<svg ')

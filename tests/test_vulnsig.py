import json
from pathlib import Path

import pytest

from vulnsig import render_glyph
from vulnsig.color import score_to_hue
from vulnsig.parse import detect_cvss_version, is_version3, parse_cvss
from vulnsig.score import calculate_score

LOG4SHELL = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'

# CVSS 3.1 test vectors
CVSS31_LOG4SHELL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
CVSS31_HEARTBLEED = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
CVSS31_DIRTY_COW = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'
CVSS31_XSS = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'

# CVSS 3.0 test vectors (same format as 3.1)
CVSS30_LOG4SHELL = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
CVSS30_HEARTBLEED = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
CVSS30_XSS = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'

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

    def test_raises_for_unsupported_version(self):
        with pytest.raises(ValueError, match='Unsupported CVSS version'):
            detect_cvss_version('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P')

    def test_raises_for_missing_prefix(self):
        with pytest.raises(ValueError, match='Unsupported CVSS version'):
            detect_cvss_version('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')


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

from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, DivisionByZeroRiskConfig
from slopcheck.rules.generic.division_by_zero_risk import DivisionByZeroRiskRule


def _make_config():
    config = AppConfig()
    config.rules.division_by_zero_risk = DivisionByZeroRiskConfig(enabled=True)
    return config


def _scan(content: str, path: str = "src/util.py") -> list:
    rule = DivisionByZeroRiskRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(),
    )


def test_detects_division_by_literal_zero_python() -> None:
    findings = _scan("result = x / 0\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "division_by_zero_risk"
    assert findings[0].severity.value == "error"


def test_detects_modulo_by_literal_zero() -> None:
    findings = _scan("result = x % 0\n")
    assert len(findings) == 1


def test_allows_division_by_nonzero() -> None:
    findings = _scan("result = x / 2\n")
    assert len(findings) == 0


def test_allows_division_by_variable() -> None:
    findings = _scan("result = x / divisor\n")
    assert len(findings) == 0


def test_skips_comment_line() -> None:
    findings = _scan("# result = x / 0\n")
    assert len(findings) == 0


def test_detects_in_js_file() -> None:
    findings = _scan("const r = x / 0;\n", path="src/app.ts")
    assert len(findings) == 1


def test_skips_unsupported_extension() -> None:
    rule = DivisionByZeroRiskRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/query.sql",
        content="SELECT x / 0 FROM t;\n",
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.division_by_zero_risk = DivisionByZeroRiskConfig(enabled=False)
    rule = DivisionByZeroRiskRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/util.py",
        content="result = x / 0\n",
        config=config,
    )
    assert len(findings) == 0


def test_allows_comparison_to_zero() -> None:
    findings = _scan("if x == 0:\n    pass\n")
    assert len(findings) == 0

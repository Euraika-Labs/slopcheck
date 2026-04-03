from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, EarlyReturnOpportunityConfig
from slopcheck.rules.generic.early_return_opportunity import EarlyReturnOpportunityRule


def _make_config(enabled: bool = True) -> AppConfig:
    config = AppConfig()
    config.rules.early_return_opportunity = EarlyReturnOpportunityConfig(enabled=enabled)
    return config


def _scan(content: str, path: str = "src/util.py", enabled: bool = True) -> list:
    rule = EarlyReturnOpportunityRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=enabled),
    )


def _make_long_if_else_return() -> str:
    """Long if-body (12 lines) then else: return."""
    body = "\n".join(f"    x = {i}" for i in range(12))
    return f"if condition:\n{body}\nelse:\n    return None\n"


def test_detects_long_if_short_else_return() -> None:
    code = _make_long_if_else_return()
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "early_return_opportunity"


def test_skips_short_if_body() -> None:
    code = "if condition:\n    x = 1\n    y = 2\nelse:\n    return None\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_long_else_body() -> None:
    body = "\n".join(f"    x = {i}" for i in range(12))
    else_body = "\n".join(f"    y = {i}" for i in range(5))
    code = f"if condition:\n{body}\nelse:\n{else_body}\n    return None\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_non_python_file() -> None:
    rule = EarlyReturnOpportunityRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.ts",
        content=_make_long_if_else_return(),
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    code = _make_long_if_else_return()
    findings = _scan(code, enabled=False)
    assert len(findings) == 0


def test_else_raise_also_flagged() -> None:
    body = "\n".join(f"    x = {i}" for i in range(12))
    code = f"if condition:\n{body}\nelse:\n    raise ValueError('bad')\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_no_else_no_finding() -> None:
    body = "\n".join(f"    x = {i}" for i in range(12))
    code = f"if condition:\n{body}\nreturn None\n"
    findings = _scan(code)
    assert len(findings) == 0

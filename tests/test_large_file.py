from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, LargeFileConfig
from slopcheck.rules.generic.large_file import LargeFileRule


def _make_config(enabled: bool = True, max_lines: int = 500) -> AppConfig:
    config = AppConfig()
    config.rules.large_file = LargeFileConfig(enabled=enabled, max_lines=max_lines)
    return config


def _scan(content: str, path: str = "src/service.py", max_lines: int = 500) -> list:
    rule = LargeFileRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=True, max_lines=max_lines),
    )


def _make_content(n: int) -> str:
    return "\n".join(f"x = {i}" for i in range(n))


def test_detects_large_python_file() -> None:
    findings = _scan(_make_content(600))
    assert len(findings) == 1
    assert findings[0].rule_id == "large_file"
    assert findings[0].location.line == 1


def test_allows_small_python_file() -> None:
    findings = _scan(_make_content(100))
    assert len(findings) == 0


def test_exactly_at_limit_no_finding() -> None:
    findings = _scan(_make_content(500))
    assert len(findings) == 0


def test_one_over_limit_finds_it() -> None:
    findings = _scan(_make_content(501))
    assert len(findings) == 1


def test_custom_max_lines() -> None:
    findings = _scan(_make_content(50), max_lines=40)
    assert len(findings) == 1


def test_skips_unsupported_extension() -> None:
    rule = LargeFileRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="README.md",
        content=_make_content(1000),
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    rule = LargeFileRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/big.py",
        content=_make_content(1000),
        config=_make_config(enabled=False),
    )
    assert len(findings) == 0


def test_detects_large_ts_file() -> None:
    findings = _scan(_make_content(600), path="src/service.ts")
    assert len(findings) == 1

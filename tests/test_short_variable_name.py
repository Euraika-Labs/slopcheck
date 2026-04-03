from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, ShortVariableNameConfig
from slopcheck.rules.generic.short_variable_name import ShortVariableNameRule


def _make_config(enabled: bool = True, allowed: list | None = None) -> AppConfig:
    config = AppConfig()
    kw = {"enabled": enabled}
    if allowed is not None:
        kw["allowed"] = allowed
    config.rules.short_variable_name = ShortVariableNameConfig(**kw)
    return config


def _scan(content: str, path: str = "src/util.py", enabled: bool = True) -> list:
    rule = ShortVariableNameRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=enabled),
    )


def test_detects_single_char_python() -> None:
    findings = _scan("a = 1\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "short_variable_name"


def test_allows_i_j_k_in_allowed() -> None:
    for name in ["i", "j", "k", "x", "y", "z", "_", "e"]:
        findings = _scan(f"{name} = 0\n")
        assert len(findings) == 0, f"{name} should be allowed"


def test_detects_single_char_js() -> None:
    findings = _scan("let a = 1;\n", path="src/app.ts")
    assert len(findings) == 1


def test_allows_longer_names_js() -> None:
    findings = _scan("let counter = 1;\n", path="src/app.ts")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = ShortVariableNameRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/style.css",
        content="a { color: red; }\n",
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    findings = _scan("a = 1\n", enabled=False)
    assert len(findings) == 0


def test_custom_allowed_list() -> None:
    config = _make_config(allowed=["i", "j", "k", "x", "y", "z", "_", "e", "a"])
    rule = ShortVariableNameRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/util.py",
        content="a = 1\n",
        config=config,
    )
    assert len(findings) == 0


def test_skips_comment_line() -> None:
    findings = _scan("# a = 1\n")
    assert len(findings) == 0

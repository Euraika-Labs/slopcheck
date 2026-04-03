from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, LargeAnonymousFunctionConfig
from slopcheck.rules.generic.large_anonymous_function import LargeAnonymousFunctionRule


def _make_config(enabled: bool = True, max_lines: int = 20) -> AppConfig:
    config = AppConfig()
    config.rules.large_anonymous_function = LargeAnonymousFunctionConfig(
        enabled=enabled, max_lines=max_lines
    )
    return config


def _make_arrow_func(n_body_lines: int) -> str:
    body = "\n".join(f"    const x{i} = {i};" for i in range(n_body_lines))
    return f"const fn = () => {{\n{body}\n}};\n"


def _scan(content: str, path: str = "src/app.ts", max_lines: int = 20) -> list:
    rule = LargeAnonymousFunctionRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(max_lines=max_lines),
    )


def test_detects_large_arrow_function() -> None:
    code = _make_arrow_func(25)
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "large_anonymous_function"


def test_allows_small_arrow_function() -> None:
    code = _make_arrow_func(10)
    findings = _scan(code)
    assert len(findings) == 0


def test_custom_max_lines() -> None:
    code = _make_arrow_func(15)
    findings = _scan(code, max_lines=10)
    assert len(findings) == 1


def test_skips_unsupported_extension() -> None:
    rule = LargeAnonymousFunctionRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.py",
        content=_make_arrow_func(30),
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    rule = LargeAnonymousFunctionRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.ts",
        content=_make_arrow_func(30),
        config=_make_config(enabled=False),
    )
    assert len(findings) == 0


def test_detects_anonymous_function_expression() -> None:
    body = "\n".join(f"    doStep{i}();" for i in range(25))
    code = f"const handler = function() {{\n{body}\n}};\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_small_function_expression_allowed() -> None:
    code = "const fn = function() {\n    return 1;\n};\n"
    findings = _scan(code)
    assert len(findings) == 0

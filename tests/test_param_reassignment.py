from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, ParamReassignmentConfig
from slopcheck.rules.generic.param_reassignment import ParamReassignmentRule


def _make_config(enabled: bool = True) -> AppConfig:
    config = AppConfig()
    config.rules.param_reassignment = ParamReassignmentConfig(enabled=enabled)
    return config


def _scan(content: str, path: str = "src/util.py", enabled: bool = True) -> list:
    rule = ParamReassignmentRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=enabled),
    )


def test_detects_param_reassignment_python() -> None:
    code = "def process(value):\n    value = value + 1\n    return value\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "param_reassignment"


def test_allows_local_variable_python() -> None:
    code = "def process(value):\n    result = value + 1\n    return result\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_param_reassignment_js() -> None:
    code = "function process(value) {\n    value = value + 1;\n    return value;\n}\n"
    findings = _scan(code, path="src/util.ts")
    assert len(findings) == 1


def test_allows_local_variable_js() -> None:
    code = "function process(value) {\n    const result = value + 1;\n    return result;\n}\n"
    findings = _scan(code, path="src/util.ts")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = ParamReassignmentRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.go",
        content="func f(x int) int { x = 1; return x }\n",
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule_no_findings() -> None:
    code = "def process(value):\n    value = 1\n    return value\n"
    findings = _scan(code, enabled=False)
    assert len(findings) == 0


def test_multiple_params_flags_correct_one() -> None:
    code = "def f(a, b):\n    b = 10\n    return a + b\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_no_findings_on_clean_function() -> None:
    code = "def f(a, b):\n    c = a + b\n    return c\n"
    findings = _scan(code)
    assert len(findings) == 0

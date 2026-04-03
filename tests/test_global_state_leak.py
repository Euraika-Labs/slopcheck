from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, GlobalStateLeakConfig
from slopcheck.rules.generic.global_state_leak import GlobalStateLeakRule


def _scan(content: str, path: str = "src/server.py") -> list:
    rule = GlobalStateLeakRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_module_level_list_python() -> None:
    code = "cache = []\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "global_state_leak"


def test_detects_module_level_dict_python() -> None:
    code = "state = {}\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_detects_let_at_module_level_js() -> None:
    code = "let counter = 0;\n"
    findings = _scan(code, path="src/handler.js")
    assert len(findings) == 1


def test_detects_var_at_module_level_ts() -> None:
    code = "var sessions = {};\n"
    findings = _scan(code, path="src/middleware.ts")
    assert len(findings) == 1


def test_skips_const_js() -> None:
    code = "const MAX = 10;\n"
    findings = _scan(code, path="src/server.ts")
    assert len(findings) == 0


def test_skips_non_server_file() -> None:
    code = "cache = []\n"
    findings = _scan(code, path="src/utils.py")
    assert len(findings) == 0


def test_skips_inside_function_python() -> None:
    code = "def handler():\n    state = {}\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.global_state_leak = GlobalStateLeakConfig(enabled=False)
    rule = GlobalStateLeakRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/server.py",
        content="cache = []\n",
        config=config,
    )
    assert len(findings) == 0


def test_skips_comment_line() -> None:
    findings = _scan("# cache = []\n")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = GlobalStateLeakRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/server.go",
        content="var state = map[string]int{}\n",
        config=AppConfig(),
    )
    assert len(findings) == 0

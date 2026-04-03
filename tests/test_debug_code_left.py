from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, DebugCodeLeftConfig
from slopcheck.rules.generic.debug_code_left import DebugCodeLeftRule


def _scan(content: str, path: str = "src/app.py") -> list:
    rule = DebugCodeLeftRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_debugger_statement() -> None:
    findings = _scan("debugger;\n", path="src/app.js")
    assert len(findings) == 1
    assert findings[0].rule_id == "debug_code_left"


def test_detects_breakpoint_call() -> None:
    findings = _scan("breakpoint()\n")
    assert len(findings) == 1


def test_detects_pdb_set_trace() -> None:
    findings = _scan("pdb.set_trace()\n")
    assert len(findings) == 1


def test_detects_console_debug() -> None:
    findings = _scan("console.debug(x)\n", path="src/app.ts")
    assert len(findings) == 1


def test_detects_import_pdb() -> None:
    findings = _scan("import pdb\n")
    assert len(findings) == 1


def test_detects_import_ipdb() -> None:
    findings = _scan("import ipdb\n")
    assert len(findings) == 1


def test_skips_test_file() -> None:
    findings = _scan("breakpoint()\n", path="tests/test_foo.py")
    assert len(findings) == 0


def test_skips_comment_line() -> None:
    findings = _scan("# breakpoint()\n")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = DebugCodeLeftRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.html",
        content="debugger;\n",
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.debug_code_left = DebugCodeLeftConfig(enabled=False)
    rule = DebugCodeLeftRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.py",
        content="breakpoint()\n",
        config=config,
    )
    assert len(findings) == 0


def test_clean_code_no_findings() -> None:
    code = "x = 1\nprint(x)\n"
    findings = _scan(code)
    assert len(findings) == 0

from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, AssignmentInConditionalConfig
from slopcheck.rules.generic.assignment_in_conditional import AssignmentInConditionalRule


def _scan(content: str, path: str = "src/app.ts") -> list:
    rule = AssignmentInConditionalRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_assignment_in_if_js() -> None:
    code = "if (x = 1) {\n    doSomething();\n}\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "assignment_in_conditional"


def test_allows_equality_check_js() -> None:
    code = "if (x == 1) {\n    doSomething();\n}\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_allows_strict_equality_js() -> None:
    code = "if (x === null) {\n    return;\n}\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_allows_not_equal_js() -> None:
    code = "if (x !== 0) {\n    return;\n}\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_in_c_file() -> None:
    code = "if (err = func()) {\n    return -1;\n}\n"
    findings = _scan(code, path="src/main.c")
    assert len(findings) == 1


def test_skips_comment_line() -> None:
    findings = _scan("// if (x = 1) { }\n")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = AssignmentInConditionalRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.py",
        content="if x = 1:\n    pass\n",
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.assignment_in_conditional = AssignmentInConditionalConfig(enabled=False)
    rule = AssignmentInConditionalRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.ts",
        content="if (x = 1) { }\n",
        config=config,
    )
    assert len(findings) == 0

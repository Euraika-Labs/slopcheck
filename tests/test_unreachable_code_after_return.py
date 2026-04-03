from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, UnreachableCodeAfterReturnConfig
from slopcheck.rules.generic.unreachable_code_after_return import UnreachableCodeAfterReturnRule


def _scan(content: str, path: str = "src/util.py") -> list:
    rule = UnreachableCodeAfterReturnRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_code_after_return_python() -> None:
    code = "def f():\n    return 1\n    x = 2\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "unreachable_code_after_return"


def test_detects_code_after_raise_python() -> None:
    code = "def f():\n    raise ValueError()\n    x = 2\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_allows_except_after_return_python() -> None:
    code = "try:\n    return 1\nexcept Exception:\n    pass\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_code_after_return_js() -> None:
    code = "function f() {\n    return 1;\n    const x = 2;\n}\n"
    findings = _scan(code, path="src/app.ts")
    assert len(findings) == 1


def test_detects_code_after_throw_js() -> None:
    code = "function f() {\n    throw new Error();\n    doSomething();\n}\n"
    findings = _scan(code, path="src/app.ts")
    assert len(findings) == 1


def test_allows_catch_after_throw_js() -> None:
    code = "try {\n    throw new Error();\n} catch (e) {\n    console.log(e);\n}\n"
    findings = _scan(code, path="src/app.ts")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = UnreachableCodeAfterReturnRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.rb",
        content="def f\n  return 1\n  x = 2\nend\n",
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.unreachable_code_after_return = UnreachableCodeAfterReturnConfig(enabled=False)
    rule = UnreachableCodeAfterReturnRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/util.py",
        content="def f():\n    return 1\n    x = 2\n",
        config=config,
    )
    assert len(findings) == 0


def test_return_at_end_of_function_no_finding() -> None:
    code = "def f():\n    x = 1\n    return x\n"
    findings = _scan(code)
    assert len(findings) == 0

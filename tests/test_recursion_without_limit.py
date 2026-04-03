from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, RecursionWithoutLimitConfig
from slopcheck.rules.generic.recursion_without_limit import RecursionWithoutLimitRule


def _make_config(enabled: bool = True) -> AppConfig:
    config = AppConfig()
    config.rules.recursion_without_limit = RecursionWithoutLimitConfig(enabled=enabled)
    return config


def _scan(content: str, path: str = "src/util.py", enabled: bool = True) -> list:
    rule = RecursionWithoutLimitRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=enabled),
    )


def test_detects_unlimited_recursion_python() -> None:
    code = "def traverse(node):\n    traverse(node.left)\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "recursion_without_limit"


def test_allows_recursion_with_depth_param() -> None:
    code = "def traverse(node, depth=0):\n    traverse(node.left, depth + 1)\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_allows_recursion_with_limit_param() -> None:
    code = "def search(items, limit):\n    search(items[1:], limit - 1)\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_unlimited_recursion_js() -> None:
    code = "function walk(node) {\n    walk(node.left);\n}\n"
    findings = _scan(code, path="src/util.ts")
    assert len(findings) == 1


def test_allows_recursion_with_depth_js() -> None:
    code = "function walk(node, depth) {\n    walk(node.left, depth + 1);\n}\n"
    findings = _scan(code, path="src/util.ts")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = RecursionWithoutLimitRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.go",
        content="func f() { f() }\n",
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    code = "def f(x):\n    return f(x - 1)\n"
    findings = _scan(code, enabled=False)
    assert len(findings) == 0


def test_no_recursion_no_finding() -> None:
    code = "def process(items):\n    return [x * 2 for x in items]\n"
    findings = _scan(code)
    assert len(findings) == 0

from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, CollectionModifyWhileIteratingConfig
from slopcheck.rules.generic.collection_modify_while_iterating import (
    CollectionModifyWhileIteratingRule,
)


def _make_config():
    config = AppConfig()
    config.rules.collection_modify_while_iterating = (
        CollectionModifyWhileIteratingConfig(enabled=True)
    )
    return config


def _scan(content: str, path: str = "src/util.py") -> list:
    rule = CollectionModifyWhileIteratingRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(),
    )


def test_detects_append_in_for_python() -> None:
    code = "for item in items:\n    items.append(item)\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "collection_modify_while_iterating"


def test_detects_remove_in_for_python() -> None:
    code = "for item in items:\n    items.remove(item)\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_allows_read_only_in_for_python() -> None:
    code = "for item in items:\n    print(item)\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_splice_in_for_js() -> None:
    code = "for (let i = 0; i < arr.length; i++) {\n    arr.splice(i, 1);\n}\n"
    findings = _scan(code, path="src/app.ts")
    assert len(findings) == 1


def test_detects_push_in_for_js() -> None:
    code = "for (const x of arr) {\n    arr.push(x);\n}\n"
    findings = _scan(code, path="src/app.js")
    assert len(findings) == 1


def test_allows_read_only_in_for_js() -> None:
    code = "for (const x of arr) {\n    console.log(x);\n}\n"
    findings = _scan(code, path="src/app.ts")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = CollectionModifyWhileIteratingRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.go",
        content="for _, v := range items { items = append(items, v) }\n",
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.collection_modify_while_iterating = CollectionModifyWhileIteratingConfig(
        enabled=False
    )
    rule = CollectionModifyWhileIteratingRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/util.py",
        content="for item in items:\n    items.append(item)\n",
        config=config,
    )
    assert len(findings) == 0

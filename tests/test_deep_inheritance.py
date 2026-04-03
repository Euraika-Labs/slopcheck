from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, DeepInheritanceConfig
from slopcheck.rules.generic.deep_inheritance import DeepInheritanceRule


def _make_config(enabled: bool = True) -> AppConfig:
    config = AppConfig()
    config.rules.deep_inheritance = DeepInheritanceConfig(enabled=enabled)
    return config


def _scan(content: str, path: str = "src/models.py", enabled: bool = True) -> list:
    rule = DeepInheritanceRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=enabled),
    )


_DEEP_CHAIN_PY = (
    "class A:\n    pass\n"
    "class B(A):\n    pass\n"
    "class C(B):\n    pass\n"
    "class D(C):\n    pass\n"
)


def test_detects_deep_chain_python() -> None:
    findings = _scan(_DEEP_CHAIN_PY)
    assert len(findings) >= 1
    assert findings[0].rule_id == "deep_inheritance"


def test_allows_shallow_chain_python() -> None:
    code = "class A:\n    pass\nclass B(A):\n    pass\nclass C(A):\n    pass\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_deep_chain_js() -> None:
    code = (
        "class A {}\n"
        "class B extends A {}\n"
        "class C extends B {}\n"
        "class D extends C {}\n"
    )
    findings = _scan(code, path="src/models.ts")
    assert len(findings) >= 1


def test_allows_depth_two_js() -> None:
    code = "class A {}\nclass B extends A {}\n"
    findings = _scan(code, path="src/models.ts")
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = DeepInheritanceRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/models.go",
        content="type A struct{}\ntype B struct{ A }\n",
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    findings = _scan(_DEEP_CHAIN_PY, enabled=False)
    assert len(findings) == 0


def test_base_object_not_counted() -> None:
    code = (
        "class A(object):\n    pass\n"
        "class B(A):\n    pass\n"
        "class C(B):\n    pass\n"
    )
    findings = _scan(code)
    # depth: C -> B -> A (object excluded) = depth 2, no finding
    assert len(findings) == 0

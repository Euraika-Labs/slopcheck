from pathlib import Path

import pytest

from slopcheck.config import AppConfig, OversizedClassConfig, RulesConfig
from slopcheck.rules.generic.oversized_class import OversizedClassRule


@pytest.fixture
def rule() -> OversizedClassRule:
    return OversizedClassRule()


@pytest.fixture
def config() -> AppConfig:
    return AppConfig()


def _py_class_with_n_methods(n: int, class_name: str = "Foo") -> str:
    methods = "\n".join(f"    def method_{i}(self): pass" for i in range(n))
    return f"class {class_name}:\n{methods}\n"


def _js_class_with_n_methods(n: int, class_name: str = "Foo") -> str:
    methods = "\n".join(f"  method{i}() {{}}" for i in range(n))
    return f"class {class_name} {{\n{methods}\n}}\n"


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def test_python_class_under_limit_no_finding(rule: OversizedClassRule, config: AppConfig) -> None:
    content = _py_class_with_n_methods(10)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


def test_python_class_over_limit_flagged(rule: OversizedClassRule, config: AppConfig) -> None:
    content = _py_class_with_n_methods(11)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "oversized_class"
    assert "11 methods" in findings[0].evidence
    assert findings[0].severity.value == "note"
    assert findings[0].confidence.value == "medium"
    assert findings[0].location.line == 1


def test_python_class_exactly_at_limit_no_finding(
    rule: OversizedClassRule, config: AppConfig
) -> None:
    content = _py_class_with_n_methods(10)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


def test_python_custom_max_methods(rule: OversizedClassRule) -> None:
    config = AppConfig(
        rules=RulesConfig(oversized_class=OversizedClassConfig(enabled=True, max_methods=5))
    )
    content = _py_class_with_n_methods(6)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert "6 methods" in findings[0].evidence


def test_python_two_classes_only_large_one_flagged(
    rule: OversizedClassRule, config: AppConfig
) -> None:
    content = _py_class_with_n_methods(3, "Small") + "\n" + _py_class_with_n_methods(12, "Large")
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert "Large" in findings[0].evidence


# ---------------------------------------------------------------------------
# JS/TS
# ---------------------------------------------------------------------------

def test_js_class_under_limit_no_finding(rule: OversizedClassRule, config: AppConfig) -> None:
    content = _js_class_with_n_methods(10)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.js",
        content=content,
        config=config,
    )
    assert findings == []


def test_js_class_over_limit_flagged(rule: OversizedClassRule, config: AppConfig) -> None:
    content = _js_class_with_n_methods(11)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.ts",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "oversized_class"


# ---------------------------------------------------------------------------
# Disabled
# ---------------------------------------------------------------------------

def test_disabled_returns_nothing(rule: OversizedClassRule) -> None:
    config = AppConfig(
        rules=RulesConfig(oversized_class=OversizedClassConfig(enabled=False))
    )
    content = _py_class_with_n_methods(20)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Extension gating
# ---------------------------------------------------------------------------

def test_unsupported_extension_returns_nothing(
    rule: OversizedClassRule, config: AppConfig
) -> None:
    content = _py_class_with_n_methods(20)
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.rb",
        content=content,
        config=config,
    )
    assert findings == []

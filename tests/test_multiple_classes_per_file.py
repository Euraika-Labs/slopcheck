from pathlib import Path

import pytest

from slopcheck.config import AppConfig, MultipleClassesPerFileConfig, RulesConfig
from slopcheck.rules.generic.multiple_classes_per_file import MultipleClassesPerFileRule


@pytest.fixture
def rule() -> MultipleClassesPerFileRule:
    return MultipleClassesPerFileRule()


@pytest.fixture
def config() -> AppConfig:
    return AppConfig()


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def test_python_single_class_no_finding(
    rule: MultipleClassesPerFileRule, config: AppConfig
) -> None:
    content = "class Foo:\n    pass\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


def test_python_two_classes_flags_second(
    rule: MultipleClassesPerFileRule, config: AppConfig
) -> None:
    content = "class Foo:\n    pass\n\nclass Bar:\n    pass\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "multiple_classes_per_file"
    assert findings[0].location.line == 4
    assert "Bar" in findings[0].evidence
    assert findings[0].confidence.value == "high"
    assert findings[0].severity.value == "note"


def test_python_three_classes_flags_second_and_third(
    rule: MultipleClassesPerFileRule, config: AppConfig
) -> None:
    content = "class A:\n    pass\n\nclass B:\n    pass\n\nclass C:\n    pass\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 2
    lines = [f.location.line for f in findings]
    assert 4 in lines
    assert 7 in lines


def test_python_nested_class_not_flagged(
    rule: MultipleClassesPerFileRule, config: AppConfig
) -> None:
    """Indented (nested) class definitions should not count as top-level."""
    content = "class Outer:\n    class Inner:\n        pass\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


def test_python_no_class_no_finding(rule: MultipleClassesPerFileRule, config: AppConfig) -> None:
    content = "def foo():\n    pass\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# JS/TS
# ---------------------------------------------------------------------------

def test_js_single_class_no_finding(rule: MultipleClassesPerFileRule, config: AppConfig) -> None:
    content = "class Foo {\n  bar() {}\n}\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.js",
        content=content,
        config=config,
    )
    assert findings == []


def test_js_two_classes_flags_second(rule: MultipleClassesPerFileRule, config: AppConfig) -> None:
    content = "class Foo {}\n\nclass Bar {}\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.ts",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].location.line == 3
    assert "Bar" in findings[0].evidence


def test_js_export_class_detected(rule: MultipleClassesPerFileRule, config: AppConfig) -> None:
    content = "export class Foo {}\n\nexport class Bar {}\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.ts",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert "Bar" in findings[0].evidence


def test_ts_indented_class_not_flagged(rule: MultipleClassesPerFileRule, config: AppConfig) -> None:
    """Class inside a block (indented) should not count as top-level."""
    content = "class Outer {\n  inner = class Inner {}\n}\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.ts",
        content=content,
        config=config,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Disabled
# ---------------------------------------------------------------------------

def test_disabled_returns_nothing(rule: MultipleClassesPerFileRule) -> None:
    config = AppConfig(
        rules=RulesConfig(
            multiple_classes_per_file=MultipleClassesPerFileConfig(enabled=False)
        )
    )
    content = "class Foo:\n    pass\n\nclass Bar:\n    pass\n"
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
    rule: MultipleClassesPerFileRule, config: AppConfig
) -> None:
    content = "class Foo:\n    pass\n\nclass Bar:\n    pass\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.rb",
        content=content,
        config=config,
    )
    assert findings == []

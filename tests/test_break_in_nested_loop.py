from pathlib import Path

import pytest

from ai_slopcheck.config import AppConfig, BreakInNestedLoopConfig, RulesConfig
from ai_slopcheck.rules.generic.break_in_nested_loop import BreakInNestedLoopRule


@pytest.fixture
def rule() -> BreakInNestedLoopRule:
    return BreakInNestedLoopRule()


@pytest.fixture
def config() -> AppConfig:
    return AppConfig()


# ---------------------------------------------------------------------------
# Python — positive cases (should flag)
# ---------------------------------------------------------------------------

def test_python_break_in_nested_for_loops(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    content = (
        "for i in range(10):\n"
        "    for j in range(10):\n"
        "        break\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "break_in_nested_loop"
    assert findings[0].location.line == 3
    assert findings[0].severity.value == "note"
    assert findings[0].confidence.value == "medium"


def test_python_break_in_while_inside_for(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    content = (
        "for item in items:\n"
        "    while condition:\n"
        "        if x:\n"
        "            break\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].location.line == 4


# ---------------------------------------------------------------------------
# Python — negative cases (should NOT flag)
# ---------------------------------------------------------------------------

def test_python_break_in_single_loop_no_finding(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    content = (
        "for i in range(10):\n"
        "    if i == 5:\n"
        "        break\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


def test_python_no_loop_no_finding(rule: BreakInNestedLoopRule, config: AppConfig) -> None:
    content = "x = 1\ny = 2\n"
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


def test_python_sequential_loops_no_finding(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    """Two loops at the same indent level are not nested."""
    content = (
        "for i in range(5):\n"
        "    pass\n"
        "for j in range(5):\n"
        "    break\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.py",
        content=content,
        config=config,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# JS — positive cases
# ---------------------------------------------------------------------------

def test_js_break_in_nested_for_loops(rule: BreakInNestedLoopRule, config: AppConfig) -> None:
    content = (
        "for (let i = 0; i < 10; i++) {\n"
        "  for (let j = 0; j < 10; j++) {\n"
        "    break;\n"
        "  }\n"
        "}\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.js",
        content=content,
        config=config,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "break_in_nested_loop"


def test_ts_break_in_while_inside_for(rule: BreakInNestedLoopRule, config: AppConfig) -> None:
    content = (
        "for (const item of items) {\n"
        "  while (condition) {\n"
        "    break;\n"
        "  }\n"
        "}\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.ts",
        content=content,
        config=config,
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# JS — negative cases
# ---------------------------------------------------------------------------

def test_js_break_in_single_loop_no_finding(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    content = (
        "for (let i = 0; i < 10; i++) {\n"
        "  if (i === 5) break;\n"
        "}\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.js",
        content=content,
        config=config,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Go — positive case
# ---------------------------------------------------------------------------

def test_go_break_in_nested_for(rule: BreakInNestedLoopRule, config: AppConfig) -> None:
    content = (
        "for i := 0; i < 10; i++ {\n"
        "    for j := 0; j < 10; j++ {\n"
        "        break\n"
        "    }\n"
        "}\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.go",
        content=content,
        config=config,
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# JS — switch inside loop (should NOT flag break)
# ---------------------------------------------------------------------------

def test_js_break_in_switch_inside_loop_no_finding(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    """break inside a switch is correct JS — not a loop break."""
    content = (
        "for (let i = 0; i < 10; i++) {\n"
        "  switch (items[i].type) {\n"
        "    case 'a':\n"
        "      break;\n"
        "    case 'b':\n"
        "      break;\n"
        "    default:\n"
        "      break;\n"
        "  }\n"
        "}\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.js",
        content=content,
        config=config,
    )
    assert findings == []


def test_js_break_in_switch_inside_nested_loops_no_finding(
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    """break in switch inside nested loops targets the switch, not a loop."""
    content = (
        "for (const row of rows) {\n"
        "  for (const col of row.cols) {\n"
        "    switch (col.kind) {\n"
        "      case 'text':\n"
        "        break;\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
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

def test_disabled_returns_nothing(rule: BreakInNestedLoopRule) -> None:
    config = AppConfig(
        rules=RulesConfig(break_in_nested_loop=BreakInNestedLoopConfig(enabled=False))
    )
    content = (
        "for i in range(10):\n"
        "    for j in range(10):\n"
        "        break\n"
    )
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
    rule: BreakInNestedLoopRule, config: AppConfig
) -> None:
    content = (
        "for i in range(10):\n"
        "    for j in range(10):\n"
        "        break\n"
    )
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/foo.rb",
        content=content,
        config=config,
    )
    assert findings == []

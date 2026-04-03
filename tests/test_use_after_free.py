from pathlib import Path

from slopcheck.config import AppConfig, RulesConfig, UseAfterFreeConfig
from slopcheck.rules.generic.use_after_free import UseAfterFreeRule


def _scan(content: str, path: str = "src/main.c", enabled: bool = True) -> list:
    rule = UseAfterFreeRule()
    config = AppConfig(
        rules=RulesConfig(
            use_after_free=UseAfterFreeConfig(enabled=enabled),
        )
    )
    return rule.scan_file(
        repo_root=Path("."),
        relative_path=path,
        content=content,
        config=config,
    )


# ---------------------------------------------------------------------------
# Positive cases — should fire
# ---------------------------------------------------------------------------

_FREE_THEN_ARROW = """\
free(node);
node->value = 0;
"""


def test_use_via_arrow_after_free() -> None:
    findings = _scan(_FREE_THEN_ARROW)
    assert len(findings) == 1
    assert findings[0].rule_id == "use_after_free"
    assert findings[0].location.line == 2


def test_use_via_deref_after_free() -> None:
    content = "free(buf);\n*buf = 'x';\n"
    findings = _scan(content)
    assert len(findings) == 1


def test_use_after_null_assignment() -> None:
    """x = NULL followed by x-> should also be flagged."""
    content = "x = NULL;\nx->field = 1;\n"
    findings = _scan(content)
    assert len(findings) == 1


def test_use_within_window() -> None:
    """Use within 10 lines of free should be caught."""
    lines = ["free(p);\n"] + ["// comment\n"] * 8 + ["p->val;\n"]
    findings = _scan("".join(lines))
    assert len(findings) == 1


def test_different_variable_not_flagged() -> None:
    """free(p) should not flag q->."""
    content = "free(p);\nq->val = 1;\n"
    findings = _scan(content)
    assert findings == []


# ---------------------------------------------------------------------------
# Negative cases — should NOT fire
# ---------------------------------------------------------------------------


def test_use_before_free_ok() -> None:
    content = "node->value = 0;\nfree(node);\n"
    findings = _scan(content)
    assert findings == []


def test_use_outside_window_ok() -> None:
    """Use more than 10 lines after free should not be reported."""
    lines = ["free(p);\n"] + ["// pad\n"] * 11 + ["p->x;\n"]
    findings = _scan("".join(lines))
    assert findings == []


def test_no_free_no_finding() -> None:
    content = "p->value = 1;\n"
    findings = _scan(content)
    assert findings == []


def test_disabled_returns_nothing() -> None:
    findings = _scan(_FREE_THEN_ARROW, enabled=False)
    assert findings == []


def test_unsupported_extension_ignored() -> None:
    rule = UseAfterFreeRule()
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="src/main.py",
        content=_FREE_THEN_ARROW,
        config=AppConfig(),
    )
    assert findings == []


def test_cpp_extension_supported() -> None:
    findings = _scan(_FREE_THEN_ARROW, path="src/main.cpp")
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Metadata checks
# ---------------------------------------------------------------------------


def test_severity_is_error() -> None:
    findings = _scan(_FREE_THEN_ARROW)
    assert findings[0].severity.value == "error"


def test_confidence_is_low() -> None:
    findings = _scan(_FREE_THEN_ARROW)
    assert findings[0].confidence.value == "low"


def test_tags_include_memory() -> None:
    findings = _scan(_FREE_THEN_ARROW)
    assert "memory" in findings[0].tags
    assert "use-after-free" in findings[0].tags

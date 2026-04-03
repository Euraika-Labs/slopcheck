from pathlib import Path

from slopcheck.config import AppConfig, ManyPositionalArgsConfig, RulesConfig
from slopcheck.rules.generic.many_positional_args import ManyPositionalArgsRule


def _make_config(**kwargs: object) -> AppConfig:
    return AppConfig(
        rules=RulesConfig(
            many_positional_args=ManyPositionalArgsConfig(**kwargs),
        )
    )


def _scan(content: str, path: str = "src/example.py", **kwargs: object) -> list:
    rule = ManyPositionalArgsRule()
    return rule.scan_file(
        repo_root=Path("."),
        relative_path=path,
        content=content,
        config=_make_config(**kwargs),
    )


# ---------------------------------------------------------------------------
# Positive cases — should fire
# ---------------------------------------------------------------------------


def test_five_positional_args_fires() -> None:
    findings = _scan("result = foo(a, b, c, d, e)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "many_positional_args"
    assert findings[0].location.line == 1


def test_six_positional_args_fires() -> None:
    findings = _scan("bar(1, 2, 3, 4, 5, 6)\n")
    assert len(findings) >= 1


def test_custom_max_positional() -> None:
    """Should fire when count exceeds custom threshold."""
    findings = _scan("f(a, b, c)\n", max_positional=2)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Negative cases — should NOT fire
# ---------------------------------------------------------------------------


def test_four_positional_args_ok() -> None:
    findings = _scan("foo(a, b, c, d)\n")
    assert findings == []


def test_keyword_args_not_counted() -> None:
    """Keyword arguments should not count toward the positional limit."""
    findings = _scan("foo(a, b, c, d, e=1)\n")
    assert findings == []


def test_all_keyword_args_ok() -> None:
    findings = _scan("connect(host=h, port=p, user=u, pw=w, db=d)\n")
    assert findings == []


def test_empty_call_ok() -> None:
    findings = _scan("foo()\n")
    assert findings == []


def test_disabled_returns_nothing() -> None:
    findings = _scan("foo(a, b, c, d, e)\n", enabled=False)
    assert findings == []


def test_unsupported_extension_ignored() -> None:
    rule = ManyPositionalArgsRule()
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="script.rb",
        content="foo(a, b, c, d, e)\n",
        config=AppConfig(),
    )
    assert findings == []


def test_nested_parens_skipped() -> None:
    """Calls with nested parens are too complex — skip to avoid false positives."""
    findings = _scan("foo(bar(x), b, c, d, e)\n")
    assert findings == []


# ---------------------------------------------------------------------------
# Metadata checks
# ---------------------------------------------------------------------------


def test_finding_severity_and_confidence() -> None:
    findings = _scan("f(a, b, c, d, e)\n")
    assert len(findings) == 1
    assert findings[0].severity.value == "note"
    assert findings[0].confidence.value == "medium"


def test_finding_tags_include_design() -> None:
    findings = _scan("f(a, b, c, d, e)\n")
    assert "design" in findings[0].tags

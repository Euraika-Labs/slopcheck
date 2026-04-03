from pathlib import Path

from slopcheck.config import AppConfig, RulesConfig, WeakFunctionNameConfig
from slopcheck.rules.generic.weak_function_name import WeakFunctionNameRule


def _scan(content: str, path: str = "src/example.py", enabled: bool = True) -> list:
    rule = WeakFunctionNameRule()
    config = AppConfig(
        rules=RulesConfig(
            weak_function_name=WeakFunctionNameConfig(enabled=enabled),
        )
    )
    return rule.scan_file(
        repo_root=Path("."),
        relative_path=path,
        content=content,
        config=config,
    )


# ---------------------------------------------------------------------------
# Exact weak names
# ---------------------------------------------------------------------------


def test_do_stuff_flagged() -> None:
    findings = _scan("def do_stuff(x):\n    pass\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "weak_function_name"
    assert findings[0].location.line == 1


def test_handle_flagged() -> None:
    findings = _scan("def handle(event):\n    pass\n")
    assert len(findings) == 1


def test_process_flagged() -> None:
    findings = _scan("def process(data):\n    return data\n")
    assert len(findings) == 1


def test_run_flagged() -> None:
    findings = _scan("def run():\n    pass\n")
    assert len(findings) == 1


def test_execute_flagged() -> None:
    findings = _scan("def execute(cmd):\n    pass\n")
    assert len(findings) == 1


def test_manage_flagged() -> None:
    findings = _scan("def manage(resource):\n    pass\n")
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Exact-match check: prefixes of weak names should NOT fire
# ---------------------------------------------------------------------------


def test_process_data_ok() -> None:
    """process_data is not an exact match for 'process' — should not fire."""
    findings = _scan("def process_data(x):\n    return x\n")
    assert findings == []


def test_handler_ok() -> None:
    """handler is not an exact match for 'handle'."""
    findings = _scan("def handler(event):\n    pass\n")
    assert findings == []


def test_run_tests_ok() -> None:
    findings = _scan("def run_tests():\n    pass\n")
    assert findings == []


# ---------------------------------------------------------------------------
# Single-letter names
# ---------------------------------------------------------------------------


def test_single_letter_a_flagged() -> None:
    findings = _scan("def a(x):\n    return x\n")
    assert len(findings) == 1


def test_single_letter_f_flagged() -> None:
    findings = _scan("def f(x):\n    return x\n")
    assert len(findings) == 1


def test_allowed_single_letters_ok() -> None:
    """i, j, k, x, y, z, _ are allowed (math/loop conventions)."""
    for letter in ("i", "j", "k", "x", "y", "z"):
        findings = _scan(f"def {letter}(n):\n    return n\n")
        assert findings == [], f"Expected no finding for def {letter}()"


# ---------------------------------------------------------------------------
# Dunder methods must never fire
# ---------------------------------------------------------------------------


def test_dunder_init_ok() -> None:
    findings = _scan("def __init__(self):\n    pass\n")
    assert findings == []


def test_dunder_str_ok() -> None:
    findings = _scan("def __str__(self):\n    return ''\n")
    assert findings == []


# ---------------------------------------------------------------------------
# Long Python function without docstring
# ---------------------------------------------------------------------------

_LONG_NO_DOC = "def compute_stuff():\n" + "    x = 1\n" * 25


def test_long_python_no_docstring_flagged() -> None:
    findings = _scan(_LONG_NO_DOC)
    # Should fire for missing docstring (25 lines > 20 limit)
    assert len(findings) == 1
    assert "no docstring" in findings[0].message


def test_long_python_with_docstring_ok() -> None:
    body = '    """Compute the answer to everything."""\n' + "    x = 1\n" * 25
    content = "def compute_stuff():\n" + body
    findings = _scan(content)
    assert findings == []


def test_short_function_no_docstring_ok() -> None:
    """Short functions (<= 20 lines) without docstring are fine."""
    content = "def compute_stuff():\n" + "    x = 1\n" * 5
    findings = _scan(content)
    assert findings == []


# ---------------------------------------------------------------------------
# JS/TS support
# ---------------------------------------------------------------------------


def test_js_named_function_handle_flagged() -> None:
    findings = _scan("function handle(e) { return e; }\n", path="src/app.js")
    assert len(findings) == 1


def test_js_arrow_run_flagged() -> None:
    findings = _scan("const run = () => { doWork(); };\n", path="src/app.ts")
    assert len(findings) == 1


def test_js_good_name_ok() -> None:
    findings = _scan(
        "function validateUserInput(input) { return !!input; }\n",
        path="src/app.ts",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Disabled / unsupported
# ---------------------------------------------------------------------------


def test_disabled_returns_nothing() -> None:
    findings = _scan("def handle(e):\n    pass\n", enabled=False)
    assert findings == []


def test_unsupported_extension_ignored() -> None:
    rule = WeakFunctionNameRule()
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="script.go",
        content="def handle(e):\n    pass\n",
        config=AppConfig(),
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_severity_and_confidence() -> None:
    findings = _scan("def run():\n    pass\n")
    assert findings[0].severity.value == "note"
    assert findings[0].confidence.value == "medium"


def test_tags_include_naming() -> None:
    findings = _scan("def execute(x):\n    pass\n")
    assert "naming" in findings[0].tags

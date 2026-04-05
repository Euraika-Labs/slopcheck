from __future__ import annotations

from pathlib import Path

from ai_slopcheck.config import AppConfig, ConsoleLogConfig
from ai_slopcheck.rules.generic.console_log_in_production import ConsoleLogInProductionRule


def _scan(content: str, path: str = "src/app.ts") -> list:
    rule = ConsoleLogInProductionRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_console_log() -> None:
    findings = _scan("  console.log('hello world');\n")
    assert len(findings) == 1
    assert "console.log(" in findings[0].evidence


def test_detects_console_warn() -> None:
    findings = _scan("  console.warn('something fishy');\n")
    assert len(findings) == 1
    assert "console.warn(" in findings[0].evidence


def test_detects_console_debug() -> None:
    findings = _scan("  console.debug('state:', state);\n")
    assert len(findings) == 1


def test_detects_console_info() -> None:
    findings = _scan("  console.info('request started');\n")
    assert len(findings) == 1


def test_does_not_flag_console_error_by_default() -> None:
    # console.error is in the default allowed_methods list.
    findings = _scan("  console.error('critical failure', err);\n")
    assert len(findings) == 0


def test_skips_test_file_by_path() -> None:
    findings = _scan("  console.log('checking output');\n", path="src/__tests__/app.test.ts")
    assert len(findings) == 0


def test_skips_spec_file_by_path() -> None:
    findings = _scan("  console.log('debug');\n", path="src/app.spec.ts")
    assert len(findings) == 0


def test_skips_fixture_file_by_path() -> None:
    findings = _scan("  console.log('data');\n", path="tests/fixtures/data.js")
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.console_log_in_production = ConsoleLogConfig(enabled=False)
    rule = ConsoleLogInProductionRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.ts",
        content="  console.log('should not flag');\n",
        config=config,
    )
    assert len(findings) == 0


def test_allowed_methods_configurable() -> None:
    # Allow log but not warn.
    config = AppConfig()
    config.rules.console_log_in_production = ConsoleLogConfig(
        enabled=True, allowed_methods=["log", "error"]
    )
    rule = ConsoleLogInProductionRule()
    findings_log = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.ts",
        content="  console.log('ok');\n",
        config=config,
    )
    findings_warn = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.ts",
        content="  console.warn('flagged');\n",
        config=config,
    )
    assert len(findings_log) == 0
    assert len(findings_warn) == 1


def test_skips_non_js_ts_extension() -> None:
    findings = _scan("console.log('hello')\n", path="src/app.py")
    assert len(findings) == 0


def test_detects_jsx_file() -> None:
    findings = _scan("  console.log(props);\n", path="src/Component.jsx")
    assert len(findings) == 1


def test_skips_worker_file() -> None:
    """Worker files are infrastructure — console.log is expected."""
    findings = _scan("console.log('worker started');\n", path="src/worker/queue.ts")
    assert len(findings) == 0


def test_skips_e2e_file() -> None:
    findings = _scan("console.log('test');\n", path="e2e/login.spec.ts")
    assert len(findings) == 0


def test_skips_conditional_logging() -> None:
    """Conditional logging gated by isDev/NODE_ENV should not flag."""
    code = "if (process.env.NODE_ENV !== 'production') console.log('debug');\n"
    findings = _scan(code)
    assert len(findings) == 0

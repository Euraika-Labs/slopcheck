from __future__ import annotations

from pathlib import Path

from ai_slopcheck.config import AppConfig, JsTimerNoCleanupConfig, RulesConfig
from ai_slopcheck.rules.generic.js_timer_no_cleanup import JsTimerNoCleanupRule


def _scan(content: str, path: str = "src/Timer.tsx") -> list:
    rule = JsTimerNoCleanupRule()
    # Rule is disabled by default — explicitly enable for tests.
    config = AppConfig(
        rules=RulesConfig(
            js_timer_no_cleanup=JsTimerNoCleanupConfig(enabled=True)
        )
    )
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=config,
    )


def test_detects_settimeout_without_cleartimeout() -> None:
    code = """\
function Timer() {
    useEffect(() => {
        setTimeout(() => setDone(true), 1000);
    }, []);
}
"""
    findings = _scan(code)
    assert len(findings) == 1
    assert "setTimeout" in findings[0].evidence


def test_detects_setinterval_without_clearinterval() -> None:
    code = """\
function Poller() {
    useEffect(() => {
        setInterval(tick, 500);
    }, []);
}
"""
    findings = _scan(code)
    assert len(findings) == 1
    assert "setInterval" in findings[0].evidence


def test_allows_settimeout_with_cleartimeout() -> None:
    code = """\
function Timer() {
    useEffect(() => {
        const id = setTimeout(() => setDone(true), 1000);
        return () => clearTimeout(id);
    }, []);
}
"""
    findings = _scan(code)
    assert len(findings) == 0


def test_allows_setinterval_with_clearinterval() -> None:
    code = """\
function Poller() {
    useEffect(() => {
        const id = setInterval(tick, 500);
        return () => clearInterval(id);
    }, []);
}
"""
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_non_jsx_tsx_files() -> None:
    rule = JsTimerNoCleanupRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/timer.ts",
        content="setTimeout(() => done(), 1000);\n",
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.js_timer_no_cleanup = JsTimerNoCleanupConfig(enabled=False)
    rule = JsTimerNoCleanupRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/Timer.tsx",
        content="setTimeout(() => setDone(true), 1000);\n",
        config=config,
    )
    assert len(findings) == 0

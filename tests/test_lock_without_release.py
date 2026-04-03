from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, LockWithoutReleaseConfig
from slopcheck.rules.generic.lock_without_release import LockWithoutReleaseRule


def _scan(content: str, path: str = "worker.py") -> list:
    rule = LockWithoutReleaseRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


# ── Python positive cases ─────────────────────────────────────────────────────

def test_py_acquire_no_release() -> None:
    code = (
        "lock.acquire()\n"
        "do_work()\n"
        "do_more_work()\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "lock" in findings[0].message


def test_py_acquire_release_in_different_branch() -> None:
    """acquire without try/finally — release exists but unprotected."""
    code = (
        "mu.acquire()\n"
        "result = compute()\n"
        "# no try/finally here\n"
        "value = result + 1\n"
        "x = 2\n"
    )
    findings = _scan(code)
    assert len(findings) == 1


# ── Python negative cases ─────────────────────────────────────────────────────

def test_py_with_statement_is_safe() -> None:
    code = (
        "with lock:\n"
        "    do_work()\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_py_acquire_with_try_finally_is_safe() -> None:
    code = (
        "lock.acquire()\n"
        "try:\n"
        "    do_work()\n"
        "finally:\n"
        "    lock.release()\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_py_acquire_with_release_in_window_is_safe() -> None:
    code = (
        "mu.acquire()\n"
        "do_work()\n"
        "mu.release()\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


# ── Go positive cases ─────────────────────────────────────────────────────────

def test_go_lock_without_defer_unlock() -> None:
    code = (
        "mu.Lock()\n"
        "x = shared_data\n"
        "return x\n"
    )
    findings = _scan(code, path="store.go")
    assert len(findings) == 1
    assert "mu" in findings[0].message


# ── Go negative cases ─────────────────────────────────────────────────────────

def test_go_lock_with_defer_unlock_is_safe() -> None:
    code = (
        "mu.Lock()\n"
        "defer mu.Unlock()\n"
        "x = shared_data\n"
    )
    findings = _scan(code, path="store.go")
    assert len(findings) == 0


def test_go_rwmutex_lock_with_defer() -> None:
    code = (
        "rw.Lock()\n"
        "defer rw.Unlock()\n"
    )
    findings = _scan(code, path="cache.go")
    assert len(findings) == 0


# ── Extension / disabled ──────────────────────────────────────────────────────

def test_skips_non_supported_extension() -> None:
    code = "lock.acquire()\ndo_work()\n"
    findings = _scan(code, path="worker.js")
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.lock_without_release = LockWithoutReleaseConfig(enabled=False)
    rule = LockWithoutReleaseRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="worker.py",
        content="lock.acquire()\ndo_work()\n",
        config=config,
    )
    assert len(findings) == 0

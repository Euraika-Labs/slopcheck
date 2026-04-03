from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python: lock.acquire() call — capture the lock variable name
_PY_ACQUIRE_RE = re.compile(r"\b(\w+)\.acquire\s*\(")

# Python safe patterns within lookahead window
_PY_WITH_RE = re.compile(r"\bwith\b")
_PY_TRY_RE = re.compile(r"^\s*try\s*:")
_PY_FINALLY_RE = re.compile(r"^\s*finally\s*:")
_PY_RELEASE_RE = re.compile(r"\b(\w+)\.release\s*\(")

# Go: mu.Lock() call — capture the mutex variable name
_GO_LOCK_RE = re.compile(r"\b(\w+)\.Lock\s*\(\s*\)")

# Go safe patterns: defer mu.Unlock() or defer mu.RUnlock()
_GO_DEFER_UNLOCK_RE = re.compile(r"\bdefer\s+(\w+)\.(?:R)?[Uu]nlock\s*\(\s*\)")

_PY_LOOKAHEAD = 15
_GO_LOOKAHEAD = 5


class LockWithoutReleaseRule(Rule):
    rule_id = "lock_without_release"
    title = "Lock acquired without guaranteed release"
    supported_extensions = {".py", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.lock_without_release
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        suffix = Path(relative_path).suffix.lower()
        lines = content.splitlines()
        findings: list[Finding] = []

        if suffix == ".py":
            findings.extend(self._scan_python(lines, relative_path))
        elif suffix == ".go":
            findings.extend(self._scan_go(lines, relative_path))

        return findings

    # ------------------------------------------------------------------
    # Python: lock.acquire() must be covered by try/finally or with
    # ------------------------------------------------------------------

    def _scan_python(self, lines: list[str], relative_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            m = _PY_ACQUIRE_RE.search(line)
            if not m:
                continue

            lock_var = m.group(1)
            window = lines[max(0, i - 3) : i + _PY_LOOKAHEAD + 1]

            # Safe if there is a "with" statement on the same line or recent context
            if _PY_WITH_RE.search(line):
                continue

            # Safe if try/finally covers the acquire, or a release appears in window
            has_try_finally = any(
                _PY_TRY_RE.match(wl) or _PY_FINALLY_RE.match(wl) for wl in window
            )
            has_release = any(
                _PY_RELEASE_RE.search(wl) and _PY_RELEASE_RE.search(wl).group(1) == lock_var  # type: ignore[union-attr]
                for wl in lines[i + 1 : i + 1 + _PY_LOOKAHEAD]
            )

            if has_try_finally or has_release:
                continue

            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=i + 1,
                    message=(
                        f"`{lock_var}.acquire()` called without a matching `try/finally` "
                        f"or `{lock_var}.release()` in the next {_PY_LOOKAHEAD} lines. "
                        "A raised exception will leave the lock permanently held."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip(),
                    suggestion=(
                        f"Use `with {lock_var}:` to guarantee release, or wrap the "
                        "critical section in `try: ... finally: lock.release()`."
                    ),
                    tags=["concurrency", "lock", "resource-leak"],
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Go: mu.Lock() must be followed by defer mu.Unlock()
    # ------------------------------------------------------------------

    def _scan_go(self, lines: list[str], relative_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            m = _GO_LOCK_RE.search(line)
            if not m:
                continue

            lock_var = m.group(1)
            window = lines[i + 1 : i + 1 + _GO_LOOKAHEAD]

            has_defer_unlock = any(
                _GO_DEFER_UNLOCK_RE.search(wl) and lock_var in wl for wl in window
            )
            if has_defer_unlock:
                continue

            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=i + 1,
                    message=(
                        f"`{lock_var}.Lock()` called without `defer {lock_var}.Unlock()` "
                        f"in the next {_GO_LOOKAHEAD} lines. "
                        "A panic or early return will leave the mutex locked."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip(),
                    suggestion=(
                        f"Add `defer {lock_var}.Unlock()` immediately after `{lock_var}.Lock()`."
                    ),
                    tags=["go", "concurrency", "lock", "resource-leak"],
                )
            )

        return findings

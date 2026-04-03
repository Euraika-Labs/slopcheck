from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Module-level mutable list or dict assignment at indent 0
# Matches: varname = []  or  varname = {}
_MODULE_MUTABLE_RE = re.compile(r"^([a-zA-Z_]\w*)\s*=\s*(?:\[\s*\]|\{\s*\})")

# Threading/async imports anywhere in the file
_THREADING_IMPORT_RE = re.compile(
    r"(?:"
    r"\bimport\s+threading\b"
    r"|\bfrom\s+threading\b"
    r"|\bimport\s+asyncio\b"
    r"|\bfrom\s+asyncio\b"
    r"|\bimport\s+concurrent\.futures\b"
    r"|\bfrom\s+concurrent(?:\.futures)?\b"
    r"|\bthreading\.Thread\b"
    r"|\basyncio\.\w"
    r"|\bconcurrent\.futures\.\w"
    r")"
)

_COMMENT_RE = re.compile(r"^\s*#")

# Known safe names that are intentionally module-level caches/registries
_SAFE_NAME_RE = re.compile(
    r"^(?:_?[A-Z][A-Z0-9_]*$"           # ALL_CAPS constants
    r"|__\w+__$"                          # dunders
    r"|logger$|log$|_log$"               # loggers
    r")"
)


def _is_inside_block(line: str) -> bool:
    """Return True if the line is indented (inside a function/class/if)."""
    return bool(line) and line[0] in (" ", "\t")


class ThreadUnsafeGlobalRule(Rule):
    rule_id = "thread_unsafe_global"
    title = "Module-level mutable state in a file that uses threading/asyncio"
    supported_extensions = {".py"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.thread_unsafe_global
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        # Only flag files that actually use threading/asyncio/concurrent
        if not _THREADING_IMPORT_RE.search(content):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        for lineno, line in enumerate(lines, start=1):
            # Skip comments and blank lines
            if not line.strip() or _COMMENT_RE.match(line):
                continue

            # Only module-level (indent 0)
            if _is_inside_block(line):
                continue

            m = _MODULE_MUTABLE_RE.match(line)
            if not m:
                continue

            var_name = m.group(1)

            # Skip ALL_CAPS constants, dunders, and loggers
            if _SAFE_NAME_RE.match(var_name):
                continue

            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        f"Module-level mutable `{var_name}` in a file that uses "
                        "threading/asyncio/concurrent.futures. "
                        "Unsynchronised reads and writes will cause data races."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip(),
                    suggestion=(
                        "Protect shared state with a `threading.Lock` or "
                        "`asyncio.Lock`, use a `threading.local()` for per-thread "
                        "storage, or move the state into a class instance."
                    ),
                    tags=["concurrency", "global-state", "thread-safety"],
                )
            )

        return findings

from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Only flag files that look like server/handler code
_SERVER_PATH_RE = re.compile(
    r"(route|handler|middleware|server|app\.(py|js|ts))",
    re.IGNORECASE,
)

# Python: module-level mutable assignment (list, dict, set) — not inside a function
_PY_MUTABLE_RE = re.compile(r"^([a-z_]\w*)\s*=\s*(?:\[\]|\{\}|set\(\))")

# JS/TS: module-level let/var (not const)
_JS_MUTABLE_RE = re.compile(r"^(?:let|var)\s+\w+\s*=")

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


class GlobalStateLeakRule(Rule):
    rule_id = "global_state_leak"
    title = "Mutable global state in server/handler file"
    supported_extensions = {".py", ".js", ".ts"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.global_state_leak
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        if not _SERVER_PATH_RE.search(relative_path):
            return []

        findings: list[Finding] = []
        suffix = Path(relative_path).suffix.lower()
        lines = content.splitlines()

        if suffix == ".py":
            # Track indent depth to stay at module level only
            in_function = False
            function_indent = 0
            for lineno, line in enumerate(lines, start=1):
                if _COMMENT_RE.match(line) or not line.strip():
                    continue
                indent = len(line) - len(line.lstrip())
                if re.match(r"^\s*(def |class )", line):
                    in_function = True
                    function_indent = indent
                    continue
                if in_function and indent <= function_indent:
                    in_function = False
                if in_function:
                    continue
                m = _PY_MUTABLE_RE.match(line)
                if m:
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=(
                                f"Module-level mutable variable `{m.group(1)}` in server file. "
                                "Shared mutable state causes race conditions"
                            ),
                            severity=Severity.WARNING,
                            confidence=Confidence.MEDIUM,
                            evidence=line.strip(),
                            suggestion=(
                                "Move state into request context, a class, or use thread-safe "
                                "primitives."
                            ),
                            tags=["global-state", "concurrency"],
                        )
                    )
        else:
            # JS/TS: flag let/var at column 0 (module level)
            for lineno, line in enumerate(lines, start=1):
                if _COMMENT_RE.match(line):
                    continue
                if _JS_MUTABLE_RE.match(line):
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=(
                                "Module-level mutable variable (`let`/`var`) in server file. "
                                "Shared mutable state causes race conditions"
                            ),
                            severity=Severity.WARNING,
                            confidence=Confidence.MEDIUM,
                            evidence=line.strip(),
                            suggestion=(
                                "Use `const` for immutable bindings, or move state into "
                                "request-scoped objects."
                            ),
                            tags=["global-state", "concurrency"],
                        )
                    )

        return findings

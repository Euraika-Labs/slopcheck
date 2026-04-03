from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python exit statements
_PY_EXIT_RE = re.compile(r"^(\s*)(return|raise|break|continue)\b")
# Lines we allow to follow an exit at the same indent (structural keywords)
_PY_STRUCTURAL_RE = re.compile(
    r"^\s*(except\b|finally\b|elif\b|else\b|#|$)"
)

# JS exit statements at end of a line (with or without semicolon)
_JS_EXIT_RE = re.compile(r"^(\s*)(return|throw|break|continue)\b[^;]*;?\s*$")
_JS_STRUCTURAL_RE = re.compile(
    r"^\s*(catch\b|finally\b|else\b|case\b|default\b|}|//|$)"
)

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


class UnreachableCodeAfterReturnRule(Rule):
    rule_id = "unreachable_code_after_return"
    title = "Unreachable code after return/throw/raise"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.unreachable_code_after_return
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        suffix = Path(relative_path).suffix.lower()
        if suffix == ".py":
            return self._scan_python(relative_path, content)
        return self._scan_js(relative_path, content)

    def _scan_python(self, relative_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = _PY_EXIT_RE.match(line)
            if not m:
                continue
            exit_indent = len(m.group(1))
            # Look at the next non-blank line
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                continue
            next_line = lines[j]
            if _PY_STRUCTURAL_RE.match(next_line):
                continue
            next_indent = len(next_line) - len(next_line.lstrip())
            if next_indent == exit_indent:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=j + 1,
                        message=(
                            f"Unreachable code after `{m.group(2)}` statement."
                        ),
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        evidence=next_line.strip(),
                        suggestion="Remove or reorder the unreachable code.",
                        tags=["unreachable-code", "dead-code"],
                    )
                )
        return findings

    def _scan_js(self, relative_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = _JS_EXIT_RE.match(line)
            if not m:
                continue
            exit_indent = len(m.group(1))
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                continue
            next_line = lines[j]
            if _JS_STRUCTURAL_RE.match(next_line):
                continue
            next_indent = len(next_line) - len(next_line.lstrip())
            if next_indent == exit_indent:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=j + 1,
                        message=(
                            f"Unreachable code after `{m.group(2)}` statement."
                        ),
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        evidence=next_line.strip(),
                        suggestion="Remove or reorder the unreachable code.",
                        tags=["unreachable-code", "dead-code"],
                    )
                )
        return findings

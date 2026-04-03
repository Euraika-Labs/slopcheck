from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python: assignment at any indent — capture the name
_PY_ASSIGN_RE = re.compile(r"^(\s*)([a-z])\s*(?::[^=]*)?=(?!=)")
# JS/TS: let/const/var declaration
_JS_ASSIGN_RE = re.compile(r"\b(?:let|const|var)\s+([a-z])\s*[=:,;)]")
# Go: short variable declaration
_GO_ASSIGN_RE = re.compile(r"\b([a-z])\s*:=")

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")

_DEFAULT_ALLOWED = frozenset(["i", "j", "k", "x", "y", "z", "_", "e"])


class ShortVariableNameRule(Rule):
    rule_id = "short_variable_name"
    title = "Single-character variable name"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.short_variable_name
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        allowed = frozenset(rule_config.allowed)
        suffix = Path(relative_path).suffix.lower()
        findings: list[Finding] = []

        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line):
                continue

            name: str | None = None
            if suffix == ".py":
                m = _PY_ASSIGN_RE.match(line)
                if m:
                    name = m.group(2)
            elif suffix == ".go":
                m = _GO_ASSIGN_RE.search(line)
                if m:
                    name = m.group(1)
            else:
                m = _JS_ASSIGN_RE.search(line)
                if m:
                    name = m.group(1)

            if name and name not in allowed:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            f"Single-character variable name `{name}`. "
                            "Use a descriptive name to improve readability."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.MEDIUM,
                        evidence=line.strip(),
                        suggestion=f"Rename `{name}` to a descriptive name.",
                        tags=["naming", "readability"],
                    )
                )

        return findings

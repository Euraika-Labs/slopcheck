from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

_IF_RE = re.compile(r"^(\s*)if\s+.+:")
_ELSE_RE = re.compile(r"^(\s*)else\s*:")
_RETURN_RAISE_RE = re.compile(r"^\s*(return|raise)\b")


class EarlyReturnOpportunityRule(Rule):
    rule_id = "early_return_opportunity"
    title = "Early return opportunity: inverted if/else"
    supported_extensions = {".py"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.early_return_opportunity
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            m = _IF_RE.match(line)
            if m:
                if_indent = len(m.group(1))
                if_start = i
                i += 1
                if_body_lines = []
                while i < len(lines):
                    body = lines[i]
                    if not body.strip():
                        i += 1
                        continue
                    body_indent = len(body) - len(body.lstrip())
                    if body_indent <= if_indent:
                        break
                    if_body_lines.append((i, body))
                    i += 1

                j = i
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines):
                    me = _ELSE_RE.match(lines[j])
                    if me and len(me.group(1)) == if_indent:
                        j += 1
                        else_body_lines = []
                        while j < len(lines):
                            body = lines[j]
                            if not body.strip():
                                j += 1
                                continue
                            body_indent = len(body) - len(body.lstrip())
                            if body_indent <= if_indent:
                                break
                            else_body_lines.append(body)
                            j += 1

                        if (
                            len(if_body_lines) > 10
                            and len(else_body_lines) < 3
                            and else_body_lines
                            and _RETURN_RAISE_RE.match(else_body_lines[0])
                        ):
                            findings.append(
                                self.build_finding(
                                    relative_path=relative_path,
                                    line=if_start + 1,
                                    message=(
                                        "Long if-body with a short else-return. "
                                        "Invert the condition and return early to reduce nesting."
                                    ),
                                    severity=Severity.NOTE,
                                    confidence=Confidence.LOW,
                                    evidence=line.strip(),
                                    suggestion=(
                                        "Invert the condition and place the short branch first "
                                        "as an early return."
                                    ),
                                    tags=["early-return", "readability"],
                                )
                            )
                continue
            i += 1
        return findings

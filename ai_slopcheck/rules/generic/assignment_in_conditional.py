from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

# Match `if (... = ...)` where = is not part of ==, !=, <=, >=
# Strategy: find `if (` then look for a bare = not preceded by [!<>=] and not followed by =
_ASSIGN_IN_IF_RE = re.compile(r"\bif\s*\([^)]*(?<![=!<>])=(?!=)[^)]*\)")
_COMMENT_RE = re.compile(r"^\s*(?://|/\*|\*)")

# Strip string and template literals to avoid matching `=` inside strings.
# Handles: 'foo=bar', "foo=bar", `foo=${bar}`
_STRING_LITERAL_RE = re.compile(
    r"""'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"|`[^`\\]*(?:\\.[^`\\]*)*`"""
)

# Arrow function expressions in conditionals: if (items.filter(x => ...))
_ARROW_FN_RE = re.compile(r"=>")


class AssignmentInConditionalRule(Rule):
    rule_id = "assignment_in_conditional"
    title = "Assignment inside conditional expression"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx", ".c", ".cc", ".cpp", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.assignment_in_conditional
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line):
                continue

            # Strip string literals so `=` inside strings doesn't trigger.
            # e.g., if (str.includes('key=value')) should not match.
            cleaned = _STRING_LITERAL_RE.sub('""', line)

            # Skip lines with arrow functions — `=>` leaves a bare `=` after stripping.
            if _ARROW_FN_RE.search(cleaned):
                continue

            if _ASSIGN_IN_IF_RE.search(cleaned):
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            "Assignment (`=`) inside an `if` condition. "
                            "Likely a typo for `==`."
                        ),
                        severity=Severity.WARNING,
                        confidence=Confidence.MEDIUM,
                        evidence=line.strip(),
                        suggestion=(
                            "Use `==` for comparison. If intentional, extract the "
                            "assignment to a separate statement before the `if`."
                        ),
                        tags=["assignment", "conditional", "typo"],
                    )
                )

        return findings

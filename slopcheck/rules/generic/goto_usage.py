from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

_GOTO_RE = re.compile(r"^\s*goto\s+\w+")
_COMMENT_RE = re.compile(r"^\s*(?://|/\*|\*)")


class GotoUsageRule(Rule):
    rule_id = "goto_usage"
    title = "goto statement used"
    supported_extensions = {".c", ".cc", ".cpp", ".h", ".hpp", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.goto_usage
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line):
                continue
            if _GOTO_RE.match(line):
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message="goto statement makes control flow hard to follow.",
                        severity=Severity.WARNING,
                        confidence=Confidence.HIGH,
                        evidence=line.strip(),
                        suggestion=(
                            "Replace goto with structured control flow "
                            "(loops, early returns, or helper functions)."
                        ),
                        tags=["goto", "control-flow"],
                    )
                )

        return findings

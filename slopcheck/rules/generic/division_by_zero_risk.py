from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Match literal division or modulo by zero: / 0 or % 0
# Avoids matching inside strings is not possible without a full parser, but
# integer literal 0 as divisor is almost always a bug.
_DIV_BY_ZERO_RE = re.compile(r"[/%]\s*0(?!\s*[\w.])")
_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*|--)")


class DivisionByZeroRiskRule(Rule):
    rule_id = "division_by_zero_risk"
    title = "Division or modulo by literal zero"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.division_by_zero_risk
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line) or not line.strip():
                continue
            if _DIV_BY_ZERO_RE.search(line):
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            "Division or modulo by literal zero detected. "
                            "This will raise a ZeroDivisionError / panic at runtime."
                        ),
                        severity=Severity.ERROR,
                        confidence=Confidence.HIGH,
                        evidence=line.strip(),
                        suggestion=(
                            "Check that the divisor is non-zero before dividing, "
                            "or replace the literal `0` with the intended value."
                        ),
                        tags=["correctness", "division-by-zero", "runtime-error"],
                    )
                )

        return findings

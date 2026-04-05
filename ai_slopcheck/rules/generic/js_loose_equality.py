from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

# Match == or != but NOT === or !==
# Uses negative lookbehind/lookahead to avoid matching === and !==
_LOOSE_EQ_RE = re.compile(r"(?<![=!<>])(?<!=)==(?!=)|(?<!!)!=(?!=)")
_COMMENT_RE = re.compile(r"^\s*(?://|/\*|\*)")

# Idiomatic JS: == null / != null checks both null and undefined. Same for == undefined.
# These are intentional and widely accepted (even by ESLint eqeqeq with "smart" option).
_NULLISH_CHECK_RE = re.compile(
    r"[!=]=\s*(?:null|undefined)\b|\b(?:null|undefined)\s*[!=]="
)


class JsLooseEqualityRule(Rule):
    rule_id = "js_loose_equality"
    title = "Loose equality operator used (== or !=)"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.js_loose_equality
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line):
                continue

            # Allow idiomatic == null / != null checks (checks both null and undefined).
            if _NULLISH_CHECK_RE.search(line):
                continue

            m = _LOOSE_EQ_RE.search(line)
            if m:
                evidence = line.strip()
                op = m.group(0)
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            f"Loose equality operator `{op}` performs type coercion. "
                            "Use strict equality instead."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                        suggestion=(
                            f"Replace `{op}` with `{'===' if op == '==' else '!=='}` "
                            "to avoid unexpected type coercion."
                        ),
                        tags=["javascript", "equality", "type-coercion"],
                    )
                )

        return findings

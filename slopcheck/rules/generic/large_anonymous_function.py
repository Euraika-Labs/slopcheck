from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Arrow function with block body: => {
_ARROW_START_RE = re.compile(r"=>\s*\{")
# Named function expression: = function(
_FUNC_EXPR_RE = re.compile(r"=\s*(?:async\s+)?function\s*\w*\s*\(")

_COMMENT_RE = re.compile(r"^\s*(?://|/\*|\*)")


class LargeAnonymousFunctionRule(Rule):
    rule_id = "large_anonymous_function"
    title = "Large anonymous or arrow function"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.large_anonymous_function
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        max_lines = rule_config.max_lines
        findings: list[Finding] = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if _COMMENT_RE.match(line):
                i += 1
                continue
            if _ARROW_START_RE.search(line) or _FUNC_EXPR_RE.search(line):
                start_lineno = i + 1
                depth = line.count("{") - line.count("}")
                # If the opening brace is on this line, count from here
                if depth <= 0:
                    i += 1
                    continue
                body_lines = 0
                i += 1
                while i < len(lines) and depth > 0:
                    body = lines[i]
                    depth += body.count("{") - body.count("}")
                    body_lines += 1
                    i += 1
                if body_lines > max_lines:
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=start_lineno,
                            message=(
                                f"Anonymous/arrow function is {body_lines} lines long "
                                f"(limit: {max_lines}). Name it or extract it."
                            ),
                            severity=Severity.NOTE,
                            confidence=Confidence.LOW,
                            evidence=lines[start_lineno - 1].strip(),
                            suggestion=(
                                "Extract the function body into a named function for "
                                "readability and testability."
                            ),
                            tags=["large-function", "anonymous-function", "readability"],
                        )
                    )
                continue
            i += 1

        return findings

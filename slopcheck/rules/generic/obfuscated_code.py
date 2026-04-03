from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

_TEST_PATH_RE = re.compile(
    r"(^|[\\/])(tests?|spec|__tests__)[\\/]|"
    r"\.(test|spec)\.(py|js|jsx|ts|tsx)$|"
    r"_test\.(py|go)$|"
    r"test_[^/\\]+\.py$",
    re.IGNORECASE,
)

# Matches eval( or exec( not preceded by a word char
_EVAL_RE = re.compile(r"(?<!\w)(eval|exec)\s*\(")
# JS Function constructor: new Function(
_FUNCTION_CTOR_RE = re.compile(r"\bnew\s+Function\s*\(")
# atob( -- base64 decode in browser JS
_ATOB_RE = re.compile(r"\batob\s*\(")
# base64 decode calls (Python)
_B64_DECODE_RE = re.compile(r"\bb64decode\s*\(|base64\.b64decode\s*\(")
# Hex escape sequences -- flag if more than 3 occur on one line
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


class ObfuscatedCodeRule(Rule):
    rule_id = "obfuscated_code"
    title = "Potentially obfuscated code detected"
    supported_extensions = None  # checked per-extension in scan_file

    _EXTENSIONS = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"})

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.obfuscated_code
        if not rule_config.enabled:
            return []

        if Path(relative_path).suffix.lower() not in self._EXTENSIONS:
            return []

        if _TEST_PATH_RE.search(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line):
                continue

            label: str | None = None
            if _EVAL_RE.search(line):
                label = "eval/exec call"
            elif _FUNCTION_CTOR_RE.search(line):
                label = "Function() constructor"
            elif _ATOB_RE.search(line):
                label = "atob() base64 decode"
            elif _B64_DECODE_RE.search(line):
                label = "base64 decode call"
            elif len(_HEX_ESCAPE_RE.findall(line)) > 3:
                label = "dense hex escape sequences"

            if label:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=f"Potentially obfuscated code: {label}.",
                        severity=Severity.WARNING,
                        confidence=Confidence.MEDIUM,
                        evidence=line.strip(),
                        suggestion=(
                            "Replace obfuscated patterns with readable code. "
                            "If intentional, add a suppression comment."
                        ),
                        tags=["obfuscation", "security"],
                    )
                )

        return findings

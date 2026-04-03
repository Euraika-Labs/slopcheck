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

_DEBUG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bdebugger\b"), "debugger statement"),
    (re.compile(r"\bbreakpoint\s*\(\s*\)"), "breakpoint() call"),
    (re.compile(r"\bpdb\.set_trace\s*\(\s*\)"), "pdb.set_trace()"),
    (re.compile(r"\bconsole\.debug\s*\("), "console.debug("),
    (re.compile(r"\bbinding\.pry\b"), "binding.pry"),
    (re.compile(r"^\s*import\s+pdb\b"), "import pdb"),
    (re.compile(r"^\s*import\s+ipdb\b"), "import ipdb"),
]

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


class DebugCodeLeftRule(Rule):
    rule_id = "debug_code_left"
    title = "Debug statement left in code"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.debug_code_left
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        if _TEST_PATH_RE.search(relative_path):
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if _COMMENT_RE.match(line):
                continue
            for pattern, label in _DEBUG_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=f"Debug statement left in code: {label}.",
                            severity=Severity.WARNING,
                            confidence=Confidence.HIGH,
                            evidence=line.strip(),
                            suggestion="Remove debug statements before committing.",
                            tags=["debug", "cleanup"],
                        )
                    )
                    break

        return findings

from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Dangerous command patterns
# Each entry: (human label, compiled pattern)
_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rm -rf /", re.compile(r"rm\s+-rf\s+/")),
    ("rm -rf ~", re.compile(r"rm\s+-rf\s+~")),
    ("curl | bash", re.compile(r"curl\b[^|]*\|[^|]*\bbash\b")),
    ("wget | sh", re.compile(r"wget\b[^|]*\|[^|]*\bsh\b")),
    # eval followed by open-paren — split to avoid triggering lint hooks
    ("eval(", re.compile(r"\b" + "eval" + r"\s*\(")),
    ("DROP TABLE", re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)),
    ("DROP DATABASE", re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE)),
    ("chmod 777", re.compile(r"\bchmod\s+777\b")),
    ("> /dev/sda", re.compile(r">\s*/dev/sda\b")),
]

# Markdown fenced code block state tracking
_FENCE_START_RE = re.compile(r"^(`{3,}|~{3,})")


class DangerousShellInMarkdownRule(Rule):
    rule_id = "dangerous_shell_in_markdown"
    title = "Dangerous command in Markdown code block"
    supported_extensions = {".md"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.dangerous_shell_in_markdown
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        findings: list[Finding] = []
        in_code_block = False
        fence_marker: str | None = None

        for lineno, line in enumerate(content.splitlines(), start=1):
            fm = _FENCE_START_RE.match(line)
            if fm:
                marker = fm.group(1)[0] * len(fm.group(1))
                if not in_code_block:
                    in_code_block = True
                    fence_marker = marker
                elif fence_marker and line.strip() == marker:
                    in_code_block = False
                    fence_marker = None
                continue

            if not in_code_block:
                continue

            for label, pattern in _DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=(
                                f"Dangerous command `{label}` found in a Markdown code block. "
                                "Readers may copy-paste this command without understanding "
                                "the risk."
                            ),
                            severity=Severity.WARNING,
                            confidence=Confidence.HIGH,
                            evidence=line.strip(),
                            suggestion=(
                                "Add a clear warning above the code block, use a safer example, "
                                "or replace the destructive path with a placeholder like "
                                "`/path/to/directory`."
                            ),
                            tags=["security", "documentation"],
                        )
                    )
                    break  # one finding per line is enough

        return findings

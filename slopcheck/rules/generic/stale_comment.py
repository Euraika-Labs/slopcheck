from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Single-line comment patterns
_PY_COMMENT_RE = re.compile(r"^\s*#\s*(.*)")
_JS_COMMENT_RE = re.compile(r"^\s*//\s*(.*)")

_WORD_RE = re.compile(r"[a-zA-Z]{3,}")  # words >= 3 chars


def _words(text: str) -> set[str]:
    return {w.lower() for w in _WORD_RE.findall(text)}


class StaleCommentRule(Rule):
    rule_id = "stale_comment"
    title = "Comment restates what the code does"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.stale_comment
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        suffix = Path(relative_path).suffix.lower()
        if suffix == ".py":
            comment_re = _PY_COMMENT_RE
        else:
            comment_re = _JS_COMMENT_RE

        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = comment_re.match(line)
            if not m:
                continue
            comment_text = m.group(1).strip()
            if not comment_text:
                continue
            # Look at the next non-blank line
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                continue
            code_line = lines[j]
            comment_words = _words(comment_text)
            code_words = _words(code_line)
            if not comment_words:
                continue
            overlap = comment_words & code_words
            ratio = len(overlap) / len(comment_words)
            if ratio >= 0.6 and len(comment_words) >= 3:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=i + 1,
                        message=(
                            "Comment may restate what the code already shows. "
                            "Comments should explain why, not what."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.LOW,
                        evidence=line.strip(),
                        suggestion=(
                            "Remove the comment if it adds no new information, or rewrite "
                            "it to explain the reasoning."
                        ),
                        tags=["comment-quality", "readability"],
                    )
                )

        return findings

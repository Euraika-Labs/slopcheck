from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Match a call: identifier(args) on a single line.
# We capture everything between the outermost parens.
_CALL_RE = re.compile(r"\b(\w+)\s*\(([^)]*)\)")


def _count_positional_args(args_str: str) -> int:
    """Count positional (non-keyword) args in a flat, single-line argument string.

    Returns 0 if the arg string appears to contain nested parens (too complex
    for reliable comma counting), or if it is empty.
    """
    stripped = args_str.strip()
    if not stripped:
        return 0

    # Split on commas; any segment containing '=' is a keyword arg.
    parts = stripped.split(",")
    positional = 0
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Keyword argument: has '=' not preceded by comparison operators.
        # Simple heuristic: contains '=' but not '==' or '!=' or '<=' or '>='
        has_kw = re.search(r"(?<![=!<>])=(?!=)", part)
        if not has_kw:
            positional += 1
    return positional


class ManyPositionalArgsRule(Rule):
    rule_id = "many_positional_args"
    title = "Too many positional arguments in function call"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.many_positional_args
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        max_positional = rule_config.max_positional
        findings: list[Finding] = []

        for lineno, line in enumerate(content.splitlines(), start=1):
            for m in _CALL_RE.finditer(line):
                func_name = m.group(1)
                args_str = m.group(2)

                # Skip if args contain nested parens — too complex for regex.
                if "(" in args_str or ")" in args_str:
                    continue

                count = _count_positional_args(args_str)
                if count > max_positional:
                    evidence = m.group(0).strip()
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=lineno,
                            message=(
                                f"`{func_name}` called with {count} positional arguments "
                                f"(max {max_positional}). Long positional argument lists are "
                                "fragile: callers must remember order, and adding a parameter "
                                "silently shifts meaning."
                            ),
                            severity=Severity.NOTE,
                            confidence=Confidence.MEDIUM,
                            evidence=evidence,
                            suggestion=(
                                "Use keyword arguments or pass a config/data object to make "
                                "the call self-documenting."
                            ),
                            tags=["design", "readability"],
                        )
                    )

        return findings

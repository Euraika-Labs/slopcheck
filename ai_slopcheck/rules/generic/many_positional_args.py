from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

# Match a call: identifier(args) on a single line.
# We capture everything between the outermost parens.
_CALL_RE = re.compile(r"\b(\w+)\s*\(([^)]*)\)")

# SQL keywords that look like function calls but aren't (VALUES(a,b,c), INSERT, etc.)
_SQL_FUNC_NAMES = frozenset({
    "VALUES", "values", "INSERT", "insert", "UPDATE", "update",
    "SELECT", "select", "DELETE", "delete", "WHERE", "where",
    "SET", "set", "IN", "in", "BETWEEN", "between",
    "COALESCE", "coalesce", "CONCAT", "concat",
    "COUNT", "count", "SUM", "sum", "AVG", "avg", "MAX", "max", "MIN", "min",
    "GROUP_CONCAT", "group_concat", "IF", "CASE",
})

# Lines that look like SQL statements — skip entirely.
_SQL_LINE_RE = re.compile(
    r"\b(?:INSERT\s+INTO|VALUES\s*\(|UPDATE\s+\w+\s+SET|SELECT\s+|DELETE\s+FROM)\b",
    re.IGNORECASE,
)

# Array/tuple literal context: line is clearly data, not a call.
_DATA_LITERAL_RE = re.compile(r"^\s*[\[\(]")

# Template literal / string interpolation context.
_STRING_CONTEXT_RE = re.compile(r"""['"`].*\b\w+\s*\([^)]*\).*['"`]""")


def _count_positional_args(args_str: str) -> int:
    """Count positional (non-keyword) args in a flat, single-line argument string.

    Returns 0 if the arg string appears to contain nested parens (too complex
    for reliable comma counting), or if it is empty.
    """
    stripped = args_str.strip()
    if not stripped:
        return 0

    # If all args are just `?` placeholders (SQL bind params), skip.
    parts = stripped.split(",")
    non_placeholder = [p.strip() for p in parts if p.strip() not in ("?", "%s", "$1", "$2",
                        "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10")]
    if not non_placeholder:
        return 0

    positional = 0
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Keyword argument: has '=' not preceded by comparison operators.
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
            # Skip lines that are clearly SQL statements.
            if _SQL_LINE_RE.search(line):
                continue

            # Skip lines that are data literals (arrays, tuples).
            if _DATA_LITERAL_RE.match(line):
                continue

            # Skip calls embedded in string literals.
            if _STRING_CONTEXT_RE.search(line):
                continue

            for m in _CALL_RE.finditer(line):
                func_name = m.group(1)
                args_str = m.group(2)

                # Skip SQL-like function names.
                if func_name in _SQL_FUNC_NAMES:
                    continue

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

from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python loop starters
_PY_LOOP_RE = re.compile(r"^( *)(?:for|while)\b")
_PY_BREAK_RE = re.compile(r"^( *)break\b")

# JS/TS/Go: lines that start a new loop scope with a brace
_BRACE_FOR_WHILE_RE = re.compile(
    r"\b(?:for|while)\s*\("
)
# Go range loops: for ... {  or for {
_GO_FOR_RE = re.compile(r"\bfor\b")

# A standalone `break` statement (not `break <label>` in Go, but we flag those too)
_BRACE_BREAK_RE = re.compile(r"\bbreak\b")

_PYTHON_EXTS = {".py"}
_BRACE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".go"}


class BreakInNestedLoopRule(Rule):
    rule_id = "break_in_nested_loop"
    title = "break inside a nested loop"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.break_in_nested_loop
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        ext = Path(relative_path).suffix.lower()
        if ext in _PYTHON_EXTS:
            return self._scan_python(relative_path, content)
        if ext in _BRACE_EXTS:
            return self._scan_brace(relative_path, content)
        return []

    # ------------------------------------------------------------------
    # Python: indent-based loop depth tracking
    # ------------------------------------------------------------------
    def _scan_python(self, relative_path: str, content: str) -> list[Finding]:
        """
        Maintain a stack of loop indents.  When we see a `for`/`while` at
        indent I, push I.  When we encounter a line whose indent is <= a
        stacked value, pop it (the loop ended).  A `break` at depth >= 2
        is flagged.
        """
        findings: list[Finding] = []
        # Stack of loop indents (int)
        loop_stack: list[int] = []

        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(stripped)

            # Pop any loops that ended (a line at indent <= loop_indent closes it)
            while loop_stack and indent <= loop_stack[-1]:
                loop_stack.pop()

            # Check for new loop
            lm = _PY_LOOP_RE.match(line)
            if lm:
                loop_stack.append(indent)
                continue

            # Check for break
            bm = _PY_BREAK_RE.match(line)
            if bm and len(loop_stack) >= 2:
                findings.append(
                    self._make_finding(
                        relative_path=relative_path,
                        lineno=lineno,
                        line=stripped,
                        depth=len(loop_stack),
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # JS/TS/Go: brace-depth loop tracking
    # ------------------------------------------------------------------
    def _scan_brace(self, relative_path: str, content: str) -> list[Finding]:
        """
        Track brace depth and a stack of brace depths at which loops opened.
        A `break` while the loop stack has >= 2 entries is flagged.
        """
        findings: list[Finding] = []
        brace_depth = 0
        # Stack of brace depths where a loop body starts
        loop_stack: list[int] = []

        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue

            opens = line.count("{")
            closes = line.count("}")

            # Detect loop keyword before counting opening brace on this line
            if _BRACE_FOR_WHILE_RE.search(line) or _GO_FOR_RE.search(line):
                # The loop body opens at brace_depth + opens (the `{` on this line)
                # We push brace_depth + opens so the body depth is > that value.
                loop_stack.append(brace_depth + opens)

            brace_depth += opens

            # Check for break
            if _BRACE_BREAK_RE.search(line) and len(loop_stack) >= 2:
                findings.append(
                    self._make_finding(
                        relative_path=relative_path,
                        lineno=lineno,
                        line=stripped,
                        depth=len(loop_stack),
                    )
                )

            brace_depth -= closes
            if brace_depth < 0:
                brace_depth = 0

            # Pop loops whose body has now closed
            while loop_stack and brace_depth < loop_stack[-1]:
                loop_stack.pop()

        return findings

    def _make_finding(
        self, *, relative_path: str, lineno: int, line: str, depth: int
    ) -> Finding:
        return self.build_finding(
            relative_path=relative_path,
            line=lineno,
            message=(
                f"`break` inside a nested loop (loop depth {depth}). "
                "This only exits the innermost loop, which is often surprising."
            ),
            severity=Severity.NOTE,
            confidence=Confidence.MEDIUM,
            evidence=line,
            suggestion=(
                "Use a flag variable, extract the loop into a function and return, "
                "or restructure the logic to avoid needing to break from an outer loop."
            ),
            tags=["correctness", "readability"],
        )

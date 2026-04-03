from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python: top-level or nested class declaration (we track its indent)
_PY_CLASS_RE = re.compile(r"^( *)class (\w+)")
# Python: def at any indent level
_PY_DEF_RE = re.compile(r"^( *)(?:async )?def (\w+)")

# JS/TS: class header (captures leading whitespace to measure class indent)
_JS_CLASS_RE = re.compile(r"^( *)(?:export\s+(?:default\s+)?)?class (\w+)")
# JS/TS: method-like lines inside a class body (one indent level deeper than class)
# Matches patterns like: methodName(, async methodName(, get foo(, set foo(, #private(
_JS_METHOD_RE = re.compile(
    r"^\s+(?:(?:static|async|get|set|override|public|private|protected|abstract)\s+)*"
    r"(?:#?\w+)\s*\("
)

_PYTHON_EXTS = {".py"}
_JS_EXTS = {".js", ".jsx", ".ts", ".tsx"}


class OversizedClassRule(Rule):
    rule_id = "oversized_class"
    title = "Class with too many methods"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.oversized_class
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        ext = Path(relative_path).suffix.lower()
        max_methods = rule_config.max_methods

        if ext in _PYTHON_EXTS:
            return self._scan_python(relative_path, content, max_methods)
        if ext in _JS_EXTS:
            return self._scan_js(relative_path, content, max_methods)
        return []

    # ------------------------------------------------------------------
    # Python scanner
    # ------------------------------------------------------------------
    def _scan_python(
        self, relative_path: str, content: str, max_methods: int
    ) -> list[Finding]:
        """
        Track class blocks by indent level.  A `def` line whose indent is
        exactly (class_indent + 4) belongs to that class.  We handle the
        common case of one nesting level and report per class.
        """
        lines = content.splitlines()

        # Collect (class_name, class_lineno, class_indent)
        class_info: list[tuple[str, int, int]] = []
        for lineno, line in enumerate(lines, start=1):
            m = _PY_CLASS_RE.match(line)
            if m:
                class_info.append((m.group(2), lineno, len(m.group(1))))

        if not class_info:
            return []

        # For each class, count defs that are at class_indent + 4
        findings: list[Finding] = []
        for idx, (class_name, class_lineno, class_indent) in enumerate(class_info):
            # Determine the line range for this class: from class_lineno to the
            # start of the next same-or-outer-level class (or end of file).
            if idx + 1 < len(class_info):
                # Next class at same or shallower indent ends our block
                next_class_lineno = class_info[idx + 1][1]
                block_lines = lines[class_lineno:next_class_lineno - 1]
            else:
                block_lines = lines[class_lineno:]

            method_indent = class_indent + 4
            method_count = 0
            for bline in block_lines:
                dm = _PY_DEF_RE.match(bline)
                if dm and len(dm.group(1)) == method_indent:
                    method_count += 1

            if method_count > max_methods:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=class_lineno,
                        message=(
                            f"Class `{class_name}` has {method_count} methods "
                            f"(max {max_methods}). Large classes are hard to maintain and test."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.MEDIUM,
                        evidence=f"class {class_name} ({method_count} methods)",
                        suggestion=(
                            "Break this class into smaller, focused classes "
                            "or extract groups of related methods into helper objects."
                        ),
                        tags=["design", "complexity"],
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # JS/TS scanner
    # ------------------------------------------------------------------
    def _scan_js(
        self, relative_path: str, content: str, max_methods: int
    ) -> list[Finding]:
        """
        Track brace depth to identify class bodies, then count method-like
        lines that are exactly one brace level deeper than the class open brace.
        """
        lines = content.splitlines()
        findings: list[Finding] = []

        # Stack entries: (class_name, class_lineno, brace_depth_at_open_brace)
        # brace_depth_at_open_brace is the depth *before* counting the `{` on
        # the class line (i.e. the depth of the surrounding scope).
        class_stack: list[tuple[str, int, int, int]] = []
        # (class_name, class_lineno, outer_depth, method_count)
        brace_depth = 0

        for lineno, line in enumerate(lines, start=1):
            # Check for a class declaration before counting braces
            cm = _JS_CLASS_RE.match(line)
            if cm:
                class_name = cm.group(2)
                # The class body opens at depth brace_depth + 1 (after the `{`)
                class_stack.append((class_name, lineno, brace_depth, 0))

            opens = line.count("{")
            closes = line.count("}")
            brace_depth += opens

            # Count methods: a method belongs to the innermost class whose body
            # depth equals (outer_depth + 1).  We only count lines that look like
            # method definitions (not nested functions or arrow assignments).
            if class_stack and _JS_METHOD_RE.match(line):
                # Method indent should be one level deeper than class indent
                innermost = class_stack[-1]
                method_body_depth = innermost[2] + 1
                # We're currently inside the class if brace_depth > outer_depth
                if brace_depth > innermost[2] and brace_depth <= method_body_depth + 1:
                    class_stack[-1] = (
                        innermost[0],
                        innermost[1],
                        innermost[2],
                        innermost[3] + 1,
                    )

            brace_depth -= closes
            if brace_depth < 0:
                brace_depth = 0

            # When a class body closes, pop the stack and emit finding if needed
            while class_stack and brace_depth <= class_stack[-1][2]:
                cn, cl, _od, mc = class_stack.pop()
                if mc > max_methods:
                    findings.append(
                        self.build_finding(
                            relative_path=relative_path,
                            line=cl,
                            message=(
                                f"Class `{cn}` has {mc} methods "
                                f"(max {max_methods}). Large classes are hard to maintain and test."
                            ),
                            severity=Severity.NOTE,
                            confidence=Confidence.MEDIUM,
                            evidence=f"class {cn} ({mc} methods)",
                            suggestion=(
                                "Break this class into smaller, focused classes "
                                "or extract groups of related methods into helper objects."
                            ),
                            tags=["design", "complexity"],
                        )
                    )

        # Flush any unclosed classes (e.g. file ended without matching `}`)
        while class_stack:
            cn, cl, _od, mc = class_stack.pop()
            if mc > max_methods:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=cl,
                        message=(
                            f"Class `{cn}` has {mc} methods "
                            f"(max {max_methods}). Large classes are hard to maintain and test."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.MEDIUM,
                        evidence=f"class {cn} ({mc} methods)",
                        suggestion=(
                            "Break this class into smaller, focused classes "
                            "or extract groups of related methods into helper objects."
                        ),
                        tags=["design", "complexity"],
                    )
                )

        return findings

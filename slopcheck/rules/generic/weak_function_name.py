from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python function definition.
_PY_DEF_RE = re.compile(r"^(\s*)def\s+(\w+)\s*\(")
# JS/TS named function declaration or method shorthand.
_JS_FUNC_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
# JS/TS: const/let/var name = (async) function | arrow
_JS_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*\(|\([^)]*\)\s*=>)"
)
# JS/TS class method shorthand: `  name(` (not a call — no preceding dot).
# We accept this at the start of an indented line to avoid too many false positives.
_JS_METHOD_RE = re.compile(r"^\s+(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{")

# Exact weak names (not substrings).
_WEAK_NAMES: frozenset[str] = frozenset(
    ["do_stuff", "handle", "process", "run", "execute", "manage"]
)

# Single-letter names that are acceptable (loop counters, math).
_ALLOWED_SINGLE_LETTERS: frozenset[str] = frozenset("ijkxyz_")

_TRIPLE_QUOTE_RE = re.compile(r'"""|\'\'\'' )


def _is_single_letter(name: str) -> bool:
    return len(name) == 1 and name not in _ALLOWED_SINGLE_LETTERS


def _has_docstring_within(lines: list[str], body_start: int, check_lines: int = 3) -> bool:
    """Return True if a triple-quote docstring appears within `check_lines` of body_start."""
    for line in lines[body_start : body_start + check_lines]:
        if _TRIPLE_QUOTE_RE.search(line):
            return True
    return False


def _py_func_length(lines: list[str], def_lineno: int, def_indent: int) -> int:
    """Return the approximate line count of a Python function starting at def_lineno (1-based)."""
    start_idx = def_lineno - 1  # 0-based
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent <= def_indent:
            return i - start_idx  # exclusive end
    return len(lines) - start_idx


class WeakFunctionNameRule(Rule):
    rule_id = "weak_function_name"
    title = "Overly generic function name"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.weak_function_name
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        ext = Path(relative_path).suffix.lower()
        lines = content.splitlines()
        findings: list[Finding] = []

        if ext == ".py":
            findings.extend(self._scan_python(relative_path, lines))
        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            findings.extend(self._scan_js(relative_path, lines))

        return findings

    # ------------------------------------------------------------------
    # Python scanning
    # ------------------------------------------------------------------

    def _scan_python(self, relative_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        for lineno, line in enumerate(lines, start=1):
            m = _PY_DEF_RE.match(line)
            if not m:
                continue

            indent = len(m.group(1))
            name = m.group(2)

            # Skip dunder methods — they are intentionally generic protocol names.
            if name.startswith("__") and name.endswith("__"):
                continue

            reason: str | None = None

            if name in _WEAK_NAMES:
                reason = f"exact weak name `{name}`"
            elif _is_single_letter(name):
                reason = f"single-letter function name `{name}`"
            else:
                # Check length + missing docstring (Python only).
                func_len = _py_func_length(lines, lineno, indent)
                if func_len > 20:
                    body_start = lineno  # 0-based: lines[lineno] is first body line
                    if not _has_docstring_within(lines, body_start, check_lines=3):
                        reason = (
                            f"function `{name}` is {func_len} lines with no docstring"
                        )

            if reason:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            f"Function has a weak or unclear name ({reason}). "
                            "Generic names make code harder to search, understand, and test."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.MEDIUM,
                        evidence=line.strip(),
                        suggestion=(
                            "Choose a name that describes what the function does "
                            "(e.g. `validate_user_input`, `render_invoice_pdf`). "
                            "Long functions without docstrings should also explain "
                            "their purpose at the top."
                        ),
                        tags=["naming", "readability", "maintainability"],
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # JS/TS scanning (named functions and assigned arrow/function expressions)
    # ------------------------------------------------------------------

    def _scan_js(self, relative_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        def emit(lineno: int, name: str, line: str, reason: str) -> None:
            key = (lineno, name)
            if key in seen:
                return
            seen.add(key)
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        f"Function has a weak or unclear name ({reason}). "
                        "Generic names make code harder to search, understand, and test."
                    ),
                    severity=Severity.NOTE,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip(),
                    suggestion=(
                        "Choose a name that describes what the function does "
                        "(e.g. `validateUserInput`, `renderInvoicePdf`)."
                    ),
                    tags=["naming", "readability", "maintainability"],
                )
            )

        for lineno, line in enumerate(lines, start=1):
            # Named function declarations.
            for m in _JS_FUNC_RE.finditer(line):
                name = m.group(1)
                if name in _WEAK_NAMES:
                    emit(lineno, name, line, f"exact weak name `{name}`")
                elif _is_single_letter(name):
                    emit(lineno, name, line, f"single-letter function name `{name}`")

            # Assigned expressions: const foo = () => { ... }
            for m in _JS_ASSIGN_RE.finditer(line):
                name = m.group(1)
                if name in _WEAK_NAMES:
                    emit(lineno, name, line, f"exact weak name `{name}`")
                elif _is_single_letter(name):
                    emit(lineno, name, line, f"single-letter function name `{name}`")

            # Class method shorthand.
            m2 = _JS_METHOD_RE.match(line)
            if m2:
                name = m2.group(1)
                if name in _WEAK_NAMES:
                    emit(lineno, name, line, f"exact weak name `{name}`")
                elif _is_single_letter(name):
                    emit(lineno, name, line, f"single-letter function name `{name}`")

        return findings

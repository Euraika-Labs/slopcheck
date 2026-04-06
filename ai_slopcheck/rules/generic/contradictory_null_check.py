from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

# Matches: if x is None:  or  if not x:  or  if len(x) == 0:
_NULL_CHECK_RE = re.compile(
    r"^(\s*)if\s+"
    r"(?:"
    r"(\w+)\s+is\s+None"           # group 2: var in "if x is None"
    r"|not\s+(\w+)"                # group 3: var in "if not x"
    r"|len\((\w+)\)\s*==\s*0"      # group 4: var in "if len(x) == 0"
    r")\s*:"
)

# Dereference: x.method( or x[
_ATTR_ACCESS_RE = re.compile(r"\b(\w+)\s*\.")
_SUBSCRIPT_RE = re.compile(r"\b(\w+)\s*\[")

# Iteration: for ... in x:
_ITER_RE = re.compile(r"\bfor\s+\w[\w,\s]*\s+in\s+(\w+)\b")

_COMMENT_RE = re.compile(r"^\s*#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


class ContradictoryNullCheckRule(Rule):
    rule_id = "contradictory_null_check"
    title = "Contradictory null/empty check: value used inside its own guard block"
    supported_extensions = {".py"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.contradictory_null_check
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        i = 0
        while i < len(lines):
            line = lines[i]
            if _COMMENT_RE.match(line) or not line.strip():
                i += 1
                continue

            m = _NULL_CHECK_RE.match(line)
            if not m:
                i += 1
                continue

            if_indent = _indent(line)
            # Determine which variable and what kind of inner check to do
            var_is_none = m.group(2)   # if x is None: → flag x.attr or x[
            var_not = m.group(3)       # if not x: → flag x.attr
            var_len = m.group(4)       # if len(x) == 0: → flag for ... in x

            guarded_var: str | None = var_is_none or var_not or var_len
            check_kind = (
                "is_none" if var_is_none
                else "not_x" if var_not
                else "len_zero"
            )

            # Collect the if-block body: lines at indent > if_indent until dedent
            j = i + 1
            while j < len(lines):
                body_line = lines[j]
                if not body_line.strip() or _COMMENT_RE.match(body_line):
                    j += 1
                    continue
                body_indent = _indent(body_line)
                if body_indent <= if_indent:
                    break  # end of block

                if guarded_var is None:
                    raise AssertionError

                if check_kind in ("is_none", "not_x"):
                    # Flag attribute access or subscript on guarded_var
                    for rx in (_ATTR_ACCESS_RE, _SUBSCRIPT_RE):
                        for hit in rx.finditer(body_line):
                            if hit.group(1) == guarded_var:
                                findings.append(
                                    self.build_finding(
                                        relative_path=relative_path,
                                        line=j + 1,
                                        message=(
                                            f"`{guarded_var}` is used at line {j + 1} but the "
                                            f"enclosing `if` at line {i + 1} guards against it "
                                            f"being None/falsy — this access will always raise."
                                        ),
                                        severity=Severity.ERROR,
                                        confidence=Confidence.MEDIUM,
                                        evidence=body_line.strip(),
                                        suggestion=(
                                            f"The `if {line.strip()[3:]}` block runs when "
                                            f"`{guarded_var}` is None or empty. "
                                            "Either invert the check or remove the dereference."
                                        ),
                                        tags=["null-check", "correctness"],
                                    )
                                )
                            break  # one finding per line per variable is enough
                else:
                    # len_zero: flag iteration over guarded_var
                    hit = _ITER_RE.search(body_line)
                    if hit and hit.group(1) == guarded_var:
                        findings.append(
                            self.build_finding(
                                relative_path=relative_path,
                                line=j + 1,
                                message=(
                                    f"`{guarded_var}` is iterated at line {j + 1} but the "
                                    f"enclosing `if len({guarded_var}) == 0` at line {i + 1} "
                                    "guarantees it is empty — this loop body never executes."
                                ),
                                severity=Severity.ERROR,
                                confidence=Confidence.MEDIUM,
                                evidence=body_line.strip(),
                                suggestion=(
                                    f"The `if len({guarded_var}) == 0` block runs only when "
                                    f"`{guarded_var}` is empty. "
                                    "Remove the loop or invert the condition."
                                ),
                                tags=["null-check", "correctness"],
                            )
                        )
                j += 1

            i += 1

        return findings

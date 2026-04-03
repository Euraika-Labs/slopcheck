from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Matches free(varname) — captures the variable name.
_FREE_RE = re.compile(r"\bfree\s*\(\s*(\w+)\s*\)")
# Matches varname = NULL (explicit null-out after free).
_NULL_ASSIGN_RE = re.compile(r"\b(\w+)\s*=\s*NULL\b")
# Matches use of a pointer: varname-> or *varname (dereference).
_USE_RE = re.compile(r"\b(\w+)\s*->|\*\s*(\w+)\b")

_WINDOW = 10  # lines to look ahead after free/null


class UseAfterFreeRule(Rule):
    rule_id = "use_after_free"
    title = "Possible use-after-free"
    supported_extensions = {".c", ".cc", ".cpp", ".h", ".hpp"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.use_after_free
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []
        # Track (variable, freed_at_lineno) pairs that are in the danger window.
        # We use a list so we can expire entries outside the window.
        freed: list[tuple[str, int]] = []  # (varname, lineno_freed)

        for lineno, line in enumerate(lines, start=1):
            # Check for uses of currently-freed variables BEFORE adding new frees on
            # this line, so `free(p); *p = 0;` on the same line is also caught.
            still_active: list[tuple[str, int]] = []
            for var, freed_at in freed:
                if lineno - freed_at > _WINDOW:
                    continue  # outside window, expire
                still_active.append((var, freed_at))
            freed = still_active

            # Check uses against the active freed set.
            for m in _USE_RE.finditer(line):
                # Group 1: var in `var->`, Group 2: var in `*var`
                used_var = m.group(1) or m.group(2)
                if not used_var:
                    continue
                for var, freed_at in freed:
                    if used_var == var:
                        evidence = line.strip()
                        findings.append(
                            self.build_finding(
                                relative_path=relative_path,
                                line=lineno,
                                message=(
                                    f"Variable `{var}` may be used after being freed "
                                    f"at line {freed_at}."
                                ),
                                severity=Severity.ERROR,
                                confidence=Confidence.LOW,
                                evidence=evidence,
                                suggestion=(
                                    f"Set `{var} = NULL` immediately after `free({var})` "
                                    "and check for NULL before dereferencing."
                                ),
                                tags=["memory", "security", "c", "use-after-free"],
                            )
                        )
                        break  # one finding per use site per variable

            # Record newly freed variables on this line.
            for m in _FREE_RE.finditer(line):
                freed.append((m.group(1), lineno))
            for m in _NULL_ASSIGN_RE.finditer(line):
                freed.append((m.group(1), lineno))

        return findings

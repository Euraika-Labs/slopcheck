from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python: capture param names from def signature
_PY_DEF_RE = re.compile(r"^(\s*)def\s+\w+\s*\(([^)]*)\)\s*(?:->.*)?:")
# JS/TS: capture param names from function signature
_JS_DEF_RE = re.compile(r"^(\s*)(?:function\s+\w+|(?:\w+\s*=\s*)?(?:async\s+)?function\s*\w*)"
                         r"\s*\(([^)]*)\)\s*\{")

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


def _extract_param_names(params_str: str) -> list[str]:
    """Extract simple parameter names from a param list string."""
    names = []
    for part in params_str.split(","):
        # Strip type annotations and defaults
        name = part.split(":")[0].split("=")[0].strip().lstrip("*").lstrip("*").strip()
        if re.match(r"^\w+$", name):
            names.append(name)
    return names


class ParamReassignmentRule(Rule):
    rule_id = "param_reassignment"
    title = "Function parameter reassigned inside function body"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.param_reassignment
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        suffix = Path(relative_path).suffix.lower()
        if suffix == ".py":
            return self._scan_python(relative_path, content)
        return self._scan_js(relative_path, content)

    def _scan_python(self, relative_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            m = _PY_DEF_RE.match(line)
            if m:
                base_indent = len(m.group(1))
                params = [
                    p for p in _extract_param_names(m.group(2))
                    if p not in ("self", "cls")
                ]
                i += 1
                while i < len(lines):
                    body_line = lines[i]
                    if not body_line.strip():
                        i += 1
                        continue
                    body_indent = len(body_line) - len(body_line.lstrip())
                    if body_indent <= base_indent:
                        break
                    if _COMMENT_RE.match(body_line):
                        i += 1
                        continue
                    for param in params:
                        assign_re = re.compile(
                            rf"^\s+{re.escape(param)}\s*(?:[+\-*/%&|^]=|=)(?!=)"
                        )
                        if assign_re.match(body_line):
                            findings.append(
                                self.build_finding(
                                    relative_path=relative_path,
                                    line=i + 1,
                                    message=(
                                        f"Parameter `{param}` is reassigned inside the function. "
                                        "Use a local variable instead."
                                    ),
                                    severity=Severity.WARNING,
                                    confidence=Confidence.MEDIUM,
                                    evidence=body_line.strip(),
                                    suggestion=(
                                        f"Introduce a local variable: "
                                        f"`result = {param}` then modify `result`."
                                    ),
                                    tags=["param-reassignment"],
                                )
                            )
                    i += 1
                continue
            i += 1
        return findings

    def _scan_js(self, relative_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            m = _JS_DEF_RE.match(line)
            if m:
                params = _extract_param_names(m.group(2))
                # Simple brace-counting to find function body
                depth = line.count("{") - line.count("}")
                i += 1
                while i < len(lines) and depth > 0:
                    body_line = lines[i]
                    depth += body_line.count("{") - body_line.count("}")
                    if not _COMMENT_RE.match(body_line):
                        for param in params:
                            assign_re = re.compile(
                                rf"\b{re.escape(param)}\s*(?:[+\-*/%&|^]=|=)(?!=)"
                            )
                            if assign_re.search(body_line):
                                findings.append(
                                    self.build_finding(
                                        relative_path=relative_path,
                                        line=i + 1,
                                        message=(
                                            f"Parameter `{param}` is reassigned inside the "
                                            "function. Use a local variable instead."
                                        ),
                                        severity=Severity.WARNING,
                                        confidence=Confidence.MEDIUM,
                                        evidence=body_line.strip(),
                                        suggestion=(
                                            f"Introduce a local variable: "
                                            f"`let result = {param}` then modify `result`."
                                        ),
                                        tags=["param-reassignment"],
                                    )
                                )
                    i += 1
                continue
            i += 1
        return findings

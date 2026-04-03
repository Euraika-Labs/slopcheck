from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python function definition
_PY_DEF_RE = re.compile(r"^(\s*)def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:")
# JS/TS function definition
_JS_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)")

_LIMIT_PARAMS = re.compile(r"\b(depth|limit|max_|level|count)\b", re.IGNORECASE)
_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


class RecursionWithoutLimitRule(Rule):
    rule_id = "recursion_without_limit"
    title = "Recursive function without depth or limit parameter"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.recursion_without_limit
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
                func_name = m.group(2)
                params_str = m.group(3)
                has_limit_param = bool(_LIMIT_PARAMS.search(params_str))
                call_re = re.compile(rf"\b{re.escape(func_name)}\s*\(")
                i += 1
                body_lines = []
                while i < len(lines):
                    body = lines[i]
                    if not body.strip():
                        i += 1
                        continue
                    body_indent = len(body) - len(body.lstrip())
                    if body_indent <= base_indent:
                        break
                    body_lines.append((i + 1, body))
                    i += 1
                if not has_limit_param:
                    for lineno, body in body_lines:
                        if not _COMMENT_RE.match(body) and call_re.search(body):
                            findings.append(
                                self.build_finding(
                                    relative_path=relative_path,
                                    line=lineno,
                                    message=(
                                        f"`{func_name}` calls itself recursively without a "
                                        "depth/limit parameter. Stack overflow risk."
                                    ),
                                    severity=Severity.NOTE,
                                    confidence=Confidence.LOW,
                                    evidence=body.strip(),
                                    suggestion=(
                                        "Add a `depth` or `limit` parameter and check it before "
                                        "recursing."
                                    ),
                                    tags=["recursion", "stack-overflow"],
                                )
                            )
                            break
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
                func_name = m.group(2)
                params_str = m.group(3)
                has_limit_param = bool(_LIMIT_PARAMS.search(params_str))
                call_re = re.compile(rf"\b{re.escape(func_name)}\s*\(")
                depth = line.count("{") - line.count("}")
                i += 1
                while i < len(lines) and depth > 0:
                    body = lines[i]
                    depth += body.count("{") - body.count("}")
                    if (
                        not has_limit_param
                        and not _COMMENT_RE.match(body)
                        and call_re.search(body)
                    ):
                        findings.append(
                            self.build_finding(
                                relative_path=relative_path,
                                line=i + 1,
                                message=(
                                    f"`{func_name}` calls itself recursively without a "
                                    "depth/limit parameter. Stack overflow risk."
                                ),
                                severity=Severity.NOTE,
                                confidence=Confidence.LOW,
                                evidence=body.strip(),
                                suggestion=(
                                    "Add a `depth` or `limit` parameter and check it before "
                                    "recursing."
                                ),
                                tags=["recursion", "stack-overflow"],
                            )
                        )
                        break
                    i += 1
                continue
            i += 1
        return findings

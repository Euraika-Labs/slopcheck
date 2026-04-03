from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# JS/TS: for loop headers
_JS_FOR_RE = re.compile(r"^\s*for\s*\(")
# JS/TS: mutation calls inside a loop body
_JS_MUTATE_RE = re.compile(r"\.(splice|push|pop|shift|unshift)\s*\(")

# Python: for loop header
_PY_FOR_RE = re.compile(r"^(\s*)for\s+\w.*\sin\s")
# Python: list mutation calls inside a loop body
_PY_MUTATE_RE = re.compile(r"\.(remove|append|pop|insert|clear|extend)\s*\(")

_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)")


class CollectionModifyWhileIteratingRule(Rule):
    rule_id = "collection_modify_while_iterating"
    title = "Collection modified while iterating"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.collection_modify_while_iterating
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
            m = _PY_FOR_RE.match(line)
            if m:
                loop_indent = len(m.group(1))
                i += 1
                while i < len(lines):
                    body = lines[i]
                    if not body.strip():
                        i += 1
                        continue
                    body_indent = len(body) - len(body.lstrip())
                    if body_indent <= loop_indent:
                        break
                    if not _COMMENT_RE.match(body) and _PY_MUTATE_RE.search(body):
                        findings.append(
                            self.build_finding(
                                relative_path=relative_path,
                                line=i + 1,
                                message=(
                                    "Collection mutated while iterating. "
                                    "This can skip items or raise RuntimeError."
                                ),
                                severity=Severity.WARNING,
                                confidence=Confidence.MEDIUM,
                                evidence=body.strip(),
                                suggestion=(
                                    "Iterate over a copy (`list(col)`) or collect changes "
                                    "and apply them after the loop."
                                ),
                                tags=["iteration", "mutation"],
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
            if _JS_FOR_RE.match(line):
                # Count braces to find the loop body
                depth = line.count("{") - line.count("}")
                i += 1
                while i < len(lines) and depth > 0:
                    body = lines[i]
                    depth += body.count("{") - body.count("}")
                    if not _COMMENT_RE.match(body) and _JS_MUTATE_RE.search(body):
                        findings.append(
                            self.build_finding(
                                relative_path=relative_path,
                                line=i + 1,
                                message=(
                                    "Array mutated while iterating with a for loop. "
                                    "This can cause items to be skipped."
                                ),
                                severity=Severity.WARNING,
                                confidence=Confidence.MEDIUM,
                                evidence=body.strip(),
                                suggestion=(
                                    "Iterate over a copy of the array, or use filter/reduce "
                                    "instead."
                                ),
                                tags=["iteration", "mutation"],
                            )
                        )
                    i += 1
                continue
            i += 1
        return findings

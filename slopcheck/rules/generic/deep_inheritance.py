from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Python: class Foo(Bar):
_PY_CLASS_RE = re.compile(r"^class\s+(\w+)\s*\(([^)]+)\)\s*:")
# JS/TS: class Foo extends Bar
_JS_CLASS_RE = re.compile(r"\bclass\s+(\w+)\s+extends\s+(\w+)")


class DeepInheritanceRule(Rule):
    rule_id = "deep_inheritance"
    title = "Deep class inheritance chain (> 2 levels)"
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.deep_inheritance
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        suffix = Path(relative_path).suffix.lower()
        if suffix == ".py":
            return self._scan_python(relative_path, content)
        return self._scan_js(relative_path, content)

    def _scan_python(self, relative_path: str, content: str) -> list[Finding]:
        # Build a map of class -> set of parent names
        parent_map: dict[str, list[str]] = {}
        class_lines: dict[str, int] = {}
        for lineno, line in enumerate(content.splitlines(), start=1):
            m = _PY_CLASS_RE.match(line)
            if m:
                cls = m.group(1)
                parents = [p.strip().split(".")[0] for p in m.group(2).split(",")]
                parents = [p for p in parents if p and p != "object"]
                parent_map[cls] = parents
                class_lines[cls] = lineno

        return self._check_chains(relative_path, parent_map, class_lines)

    def _scan_js(self, relative_path: str, content: str) -> list[Finding]:
        parent_map: dict[str, list[str]] = {}
        class_lines: dict[str, int] = {}
        for lineno, line in enumerate(content.splitlines(), start=1):
            m = _JS_CLASS_RE.search(line)
            if m:
                cls = m.group(1)
                parent = m.group(2)
                parent_map[cls] = [parent]
                class_lines[cls] = lineno

        return self._check_chains(relative_path, parent_map, class_lines)

    def _chain_depth(self, cls: str, parent_map: dict[str, list[str]],
                     visited: set[str]) -> int:
        if cls in visited or cls not in parent_map:
            return 0
        visited.add(cls)
        parents = parent_map[cls]
        if not parents:
            return 0
        return 1 + max(self._chain_depth(p, parent_map, visited) for p in parents)

    def _check_chains(
        self,
        relative_path: str,
        parent_map: dict[str, list[str]],
        class_lines: dict[str, int],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for cls, lineno in class_lines.items():
            depth = self._chain_depth(cls, parent_map, set())
            if depth > 2:
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            f"Class `{cls}` has an inheritance chain deeper than 2 levels "
                            f"(depth={depth}). Deep inheritance makes code hard to follow."
                        ),
                        severity=Severity.NOTE,
                        confidence=Confidence.LOW,
                        evidence=f"class {cls} (depth={depth})",
                        suggestion=(
                            "Prefer composition over inheritance to reduce coupling."
                        ),
                        tags=["inheritance", "design"],
                    )
                )
        return findings

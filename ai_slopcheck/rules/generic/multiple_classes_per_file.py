from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

# Python: top-level class (no leading whitespace)
_PY_CLASS_RE = re.compile(r"^class (\w+)")
# JS/TS: top-level class, with optional export keyword, no leading whitespace
_JS_CLASS_RE = re.compile(r"^(?:export\s+(?:default\s+)?)?class (\w+)")

_PYTHON_EXTS = {".py"}
_JS_EXTS = {".js", ".jsx", ".ts", ".tsx"}


class MultipleClassesPerFileRule(Rule):
    rule_id = "multiple_classes_per_file"
    title = "Multiple top-level classes in a single file"
    # Excludes .jsx/.tsx: React components rarely use classes, and colocating
    # helper classes (ErrorBoundary, HOC wrappers) in the same file is standard.
    supported_extensions = {".py", ".js", ".ts"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.multiple_classes_per_file
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        ext = Path(relative_path).suffix.lower()
        if ext in _PYTHON_EXTS:
            pattern = _PY_CLASS_RE
        elif ext in _JS_EXTS:
            pattern = _JS_CLASS_RE
        else:
            return []

        class_lines: list[tuple[int, str]] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            m = pattern.match(line)
            if m:
                class_lines.append((lineno, m.group(1)))

        if len(class_lines) <= 1:
            return []

        findings: list[Finding] = []
        for lineno, class_name in class_lines[1:]:
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        f"File contains multiple top-level classes. "
                        f"`{class_name}` is class "
                        f"#{class_lines.index((lineno, class_name)) + 1} "
                        f"(first: `{class_lines[0][1]}`). "
                        "Each file should define exactly one top-level class."
                    ),
                    severity=Severity.NOTE,
                    confidence=Confidence.HIGH,
                    evidence=f"class {class_name}",
                    suggestion=(
                        "Move each class into its own module to improve navigability "
                        "and keep files focused."
                    ),
                    tags=["design", "structure"],
                )
            )
        return findings


def _ordinal(n: int) -> str:
    suffixes = {1: "st", 2: "nd", 3: "rd"}
    return f"{n}{suffixes.get(n if n < 20 else n % 10, 'th')}"

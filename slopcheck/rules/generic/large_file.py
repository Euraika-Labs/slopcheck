from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

_CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".java", ".rb", ".php", ".cs", ".swift",
})


class LargeFileRule(Rule):
    rule_id = "large_file"
    title = "File exceeds recommended line count"
    supported_extensions = None  # checked per-extension in scan_file

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.large_file
        if not rule_config.enabled:
            return []

        if Path(relative_path).suffix.lower() not in _CODE_EXTENSIONS:
            return []

        lines = content.splitlines()
        count = len(lines)
        if count <= rule_config.max_lines:
            return []

        return [
            self.build_finding(
                relative_path=relative_path,
                line=1,
                message=(
                    f"File has {count} lines, exceeding the limit of "
                    f"{rule_config.max_lines}. Consider splitting it."
                ),
                severity=Severity.NOTE,
                confidence=Confidence.HIGH,
                evidence=f"{count} lines",
                suggestion=(
                    "Split the file into smaller modules with focused responsibilities."
                ),
                tags=["large-file", "maintainability"],
            )
        ]

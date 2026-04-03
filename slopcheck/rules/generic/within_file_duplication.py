from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

_CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".java", ".rb", ".php",
})


class WithinFileDuplicationRule(Rule):
    rule_id = "within_file_duplication"
    title = "Duplicate code block within the same file"
    supported_extensions = None  # checked per-extension in scan_file

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.within_file_duplication
        if not rule_config.enabled:
            return []

        if Path(relative_path).suffix.lower() not in _CODE_EXTENSIONS:
            return []

        min_lines = rule_config.min_lines
        lines = content.splitlines()
        if len(lines) < min_lines * 2:
            return []

        # Build map: hash -> [start_lineno, ...]
        window_map: dict[str, list[int]] = {}
        for i in range(len(lines) - min_lines + 1):
            window = lines[i:i + min_lines]
            # Skip windows that are mostly blank
            if sum(1 for ln in window if ln.strip()) < min_lines // 2:
                continue
            key = sha256("\n".join(window).encode()).hexdigest()
            window_map.setdefault(key, []).append(i + 1)

        reported: set[str] = set()
        findings: list[Finding] = []
        for key, positions in window_map.items():
            if len(positions) < 2:
                continue
            # Only report each block once
            if key in reported:
                continue
            reported.add(key)
            first, second = positions[0], positions[1]
            # Evidence: first non-blank line of the block
            block_lines = lines[first - 1:first - 1 + min_lines]
            evidence = next((ln.strip() for ln in block_lines if ln.strip()), "")
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=second,
                    message=(
                        f"Duplicate {min_lines}-line block found at lines "
                        f"{first} and {second}."
                    ),
                    severity=Severity.NOTE,
                    confidence=Confidence.MEDIUM,
                    evidence=evidence,
                    suggestion=(
                        "Extract the duplicated block into a shared function."
                    ),
                    tags=["duplication", "dry"],
                )
            )

        return findings

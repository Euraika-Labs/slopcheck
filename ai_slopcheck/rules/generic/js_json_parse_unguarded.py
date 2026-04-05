from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

_JSON_PARSE_RE = re.compile(r"JSON\.parse\s*\(")
_TRY_CATCH_RE = re.compile(r"\b(?:try|catch)\b")

# Safe-parse wrapper patterns — if the file defines or imports a safe parser, skip.
_SAFE_PARSE_RE = re.compile(
    r"\b(?:safeJsonParse|safeParse|tryParse|parseJSON|jsonSafeParse)\b", re.IGNORECASE
)

# Known-safe sources: Prisma JSON fields, response.json(), Buffer.toString(), etc.
_SAFE_SOURCE_RE = re.compile(
    r"JSON\.parse\s*\(\s*(?:"
    r"(?:\w+\.(?:json|text|body|data|toString|stringify|value|result|content))"
    r"|(?:JSON\.stringify)"
    r"|(?:await\s+\w+\.(?:json|text)\(\))"
    r")\s*\)"
)


class JsJsonParseUnguardedRule(Rule):
    rule_id = "js_json_parse_unguarded"
    title = "Unguarded JSON.parse call"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.js_json_parse_unguarded
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        # If the file defines or imports a safe-parse wrapper, skip all findings.
        if _SAFE_PARSE_RE.search(content):
            return []

        for lineno, line in enumerate(lines, start=1):
            if not _JSON_PARSE_RE.search(line):
                continue

            # Skip JSON.parse of known-safe sources (e.g., response.json(), Prisma fields).
            if _SAFE_SOURCE_RE.search(line):
                continue

            # Check 15 lines above and 15 lines below for try/catch (expanded from 3).
            start = max(0, lineno - 16)  # lineno is 1-based
            end = min(len(lines), lineno + 15)
            context_lines = lines[start:end]

            has_guard = any(_TRY_CATCH_RE.search(ctx) for ctx in context_lines)
            if not has_guard:
                evidence = line.strip()
                findings.append(
                    self.build_finding(
                        relative_path=relative_path,
                        line=lineno,
                        message=(
                            "JSON.parse() called without a surrounding try/catch. "
                            "Invalid JSON input will throw a SyntaxError at runtime."
                        ),
                        severity=Severity.WARNING,
                        confidence=Confidence.MEDIUM,
                        evidence=evidence,
                        suggestion=(
                            "Wrap JSON.parse() in a try/catch block, or use a safe-parse "
                            "helper that returns null/undefined on failure."
                        ),
                        tags=["javascript", "error-handling"],
                    )
                )

        return findings

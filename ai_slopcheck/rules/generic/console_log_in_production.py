from __future__ import annotations

import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.rules.base import Rule

# Matches console.METHOD( where METHOD is captured.
_CONSOLE_RE = re.compile(r"\bconsole\.(log|warn|debug|info|error)\s*\(")

# Path segments that indicate test/fixture/mock/infra files — skip these.
_SKIP_PATH_SEGMENTS = (
    "test", "spec", "fixture", "mock", "__mocks__", "__tests__",
    "script", "cli", "bin", "tool", "build", "config",
    "setup", "migration", "seed", "gulp", "webpack",
    "vite.config", "next.config", "jest.config",
    "eslint", "prettier", "babel",
    # Logger implementations intentionally wrap console.*
    "logger", "logging", "log.ts", "log.js", "log.tsx",
    "debug.ts", "debug.js",
    # Workers, agents, e2e tests, and infrastructure
    "worker", "e2e", "agent", "docs", "example",
    "cypress", "playwright", "puppeteer",
)

# Conditional logging is intentional — if (isDev) console.log()
_CONDITIONAL_LOG_RE = re.compile(
    r"\bif\s*\(.*(?:isDev|isDebug|DEBUG|NODE_ENV|__DEV__|process\.env)"
)


class ConsoleLogInProductionRule(Rule):
    rule_id = "console_log_in_production"
    title = "console.log (or similar) left in production code"
    supported_extensions = {".js", ".jsx", ".ts", ".tsx"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.console_log_in_production
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        lower_path = relative_path.lower()
        if any(seg in lower_path for seg in _SKIP_PATH_SEGMENTS):
            return []

        # Build the set of methods to allow (not flag).
        allowed = {m.lower() for m in rule_config.allowed_methods}

        findings: list[Finding] = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            # Skip commented-out console statements
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            # Skip conditional logging (e.g., if (isDev) console.log())
            if _CONDITIONAL_LOG_RE.search(line):
                continue
            # Also check previous line for conditional guard
            if lineno >= 2 and _CONDITIONAL_LOG_RE.search(lines[lineno - 2]):
                continue
            m = _CONSOLE_RE.search(line)
            if not m:
                continue
            method = m.group(1).lower()
            if method in allowed:
                continue
            evidence = m.group(0)
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        f"`{evidence}` found in production code. "
                        "Console logging statements should be removed before shipping "
                        "to avoid leaking internal state and cluttering browser output."
                    ),
                    severity=Severity.NOTE,
                    confidence=Confidence.MEDIUM,
                    evidence=evidence,
                    suggestion=(
                        f"Remove `{evidence}` or replace it with a proper logger "
                        "that can be disabled in production builds."
                    ),
                    tags=["console", "logging", "javascript"],
                )
            )
        return findings

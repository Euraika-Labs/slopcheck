from __future__ import annotations

import math
import re
from pathlib import Path

from ai_slopcheck.config import AppConfig
from ai_slopcheck.models import Confidence, Finding, Severity
from ai_slopcheck.parsers.treesitter import is_in_comment
from ai_slopcheck.rules.base import Rule

# Key names that suggest a secret is being assigned
_SECRET_KEY_RE = re.compile(
    r"""(?:password|passwd|secret(?:_key)?|api_key|apikey|auth_token|access_token"""
    r"""|private_key|client_secret)\s*[=:]\s*['"]([^'"]{4,})['"]""",
    re.IGNORECASE,
)

# Placeholder strings that are clearly not real secrets.
# Expanded to catch common documentation examples and test fixtures.
_PLACEHOLDER_RE = re.compile(
    r"""(?:your[-_]|REPLACE|CHANGE[-_]?ME|<[^>]+>|example|xxx+|todo|changeme"""
    r"""|placeholder|insert[-_]|dummy|fake|test|sample|\.\.\.|N/A"""
    r"""|password\d+|secret\d+|abc\d+|123|my[-_]?secret|my[-_]?password"""
    r"""|sk[-_]test|pk[-_]test|key[-_]here|fill[-_]in|update[-_]me"""
    r"""|CHANGE|FIXME|HACK)""",
    re.IGNORECASE,
)

# Shannon entropy threshold: values above this are "high entropy" (more suspicious)
_ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# Path segments that identify test, fixture, or documentation files — skip those.
_TEST_PATH_SEGMENTS = (
    "test", "fixture", "mock", "stub", "example", "spec",
    "seed", "sample", "generated", "vendor", "__generated__",
    "docs", "doc", "README", "CONTRIBUTING", "CHANGELOG",
)

# File extensions for documentation — skip these entirely.
_DOC_EXTENSIONS = frozenset({".md", ".mdx", ".rst", ".txt", ".adoc"})

# Lines that are error messages, log statements, or validation — not real secrets.
_ERROR_LOG_RE = re.compile(
    r"""\b(?:throw\b|Error\s*\(|console\.|logger?\.|log\s*\.|warn\s*\("""
    r"""|raise\b|logging\.|print\s*\()""",
    re.IGNORECASE,
)


class HardcodedSecretRule(Rule):
    rule_id = "hardcoded_secret"
    title = "Hardcoded secret or credential"
    supported_extensions = None  # all file types

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.hardcoded_secret
        if not rule_config.enabled:
            return []

        lower_path = relative_path.lower()
        if any(seg in lower_path for seg in _TEST_PATH_SEGMENTS):
            return []

        # Skip documentation files — they commonly show placeholder credentials.
        if Path(relative_path).suffix.lower() in _DOC_EXTENSIONS:
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            m = _SECRET_KEY_RE.search(line)
            if not m:
                continue
            # Skip lines that are error messages, log statements, or validation output.
            if _ERROR_LOG_RE.search(line):
                continue
            # Tree-sitter: skip matches inside comments
            ext = Path(relative_path).suffix.lower()
            ts_result = is_in_comment(content, ext, lineno, m.start())
            if ts_result is True:
                continue
            value = m.group(1)
            # Skip obvious placeholders
            if _PLACEHOLDER_RE.search(value):
                continue
            # Skip enum/type definitions where value equals key name
            # e.g., ApiKey = 'ApiKey' or password = 'password'
            key_name = re.split(r"\s*[=:]", line.strip())[0].strip()
            key_base = key_name.split(".")[-1].strip()
            if value.lower() == key_base.lower():
                continue
            # Skip very short values (< 6 chars) — likely enum/config
            if len(value) < 6:
                continue
            entropy = _shannon_entropy(value)
            confidence = Confidence.HIGH if entropy > _ENTROPY_THRESHOLD else Confidence.MEDIUM
            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=lineno,
                    message=(
                        f"Hardcoded secret assigned to `{key_name}`. "
                        f"Shannon entropy of the value is {entropy:.2f} bits/char."
                    ),
                    severity=Severity.ERROR,
                    confidence=confidence,
                    evidence=f"{key_name} = <redacted>",
                    suggestion=(
                        "Move secrets to environment variables or a secrets manager. "
                        "Never commit real credentials."
                    ),
                    tags=["hardcoded-secret", "security"],
                )
            )
        return findings

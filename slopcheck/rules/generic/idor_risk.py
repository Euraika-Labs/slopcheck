from __future__ import annotations

import re
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Only scan files whose path suggests they are route/view/handler/API code
_ROUTE_PATH_RE = re.compile(
    r"(?:route|view|handler|api)",
    re.IGNORECASE,
)

# Request parameter extraction patterns
_PARAM_EXTRACT_RE = re.compile(
    r"(?:"
    r"request\.(?:params|query|args|GET|POST|data|form|json)"  # Django/Flask/FastAPI
    r"|req\.(?:params|query|body|headers)"                     # Express
    r"|params\[|query\[|args\["                                # direct subscript
    r"|params\.get\(|query\.get\(|args\.get\("                # .get() access
    r")"
)

# DB call patterns
_DB_CALL_RE = re.compile(
    r"(?:"
    r"\.query\s*\("
    r"|\.execute\s*\("
    r"|\.filter\s*\("
    r"|\.filter_by\s*\("
    r"|\.get\s*\("
    r"|\.find\s*\("
    r"|\.find_one\s*\("
    r"|\.findOne\s*\("
    r"|\.findById\s*\("
    r"|\bdb\."
    r"|\bsession\."
    r"|\.objects\."
    r")"
)

# Auth/authorization check patterns — presence anywhere in the lookahead window
_AUTH_CHECK_RE = re.compile(
    r"(?:"
    r"\bauthorize\b"
    r"|\bcheck_permission\b"
    r"|\bcurrent_user\b"
    r"|\bverify_owner\b"
    r"|\bhas_permission\b"
    r"|\brequire_auth\b"
    r"|\bpermission_required\b"
    r"|\blogin_required\b"
    r"|\bget_object_or_404\b"
    r"|\bHttpRequest\.user\b"
    r"|\brequest\.user\b"
    r"|\buser_id\s*==\s*"
    r"|\bcurrent_user\b"
    r"|\bauth\."
    r")"
)

_LOOKAHEAD = 15
_LOOKBACK = 5  # also check a few lines before the DB call


class IdorRiskRule(Rule):
    rule_id = "idor_risk"
    title = "Potential IDOR: request parameter used in DB call without visible auth check"
    supported_extensions = {".py", ".js", ".ts"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.idor_risk
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        # Only applies to route/view/handler/api files
        if not _ROUTE_PATH_RE.search(relative_path):
            return []

        lines = content.splitlines()
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            if not _PARAM_EXTRACT_RE.search(line):
                continue

            # Look ahead for a DB call
            db_hit_line: int | None = None
            for k in range(i + 1, min(i + 1 + _LOOKAHEAD, len(lines))):
                if _DB_CALL_RE.search(lines[k]):
                    db_hit_line = k
                    break

            if db_hit_line is None:
                continue

            # Check a window around both lines for an auth check
            window_start = max(0, i - _LOOKBACK)
            window_end = min(len(lines), db_hit_line + 1 + _LOOKBACK)
            window = lines[window_start:window_end]

            has_auth = any(_AUTH_CHECK_RE.search(wl) for wl in window)
            if has_auth:
                continue

            findings.append(
                self.build_finding(
                    relative_path=relative_path,
                    line=i + 1,
                    message=(
                        f"Request parameter extracted at line {i + 1} and used in a DB call "
                        f"at line {db_hit_line + 1} without a visible authorization check. "
                        "This may allow one authenticated user to access another's data (IDOR)."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.LOW,
                    evidence=line.strip(),
                    suggestion=(
                        "Verify the requesting user owns or has permission to access the "
                        "requested resource before performing the DB query. "
                        "Use an explicit ownership check or scope the query to `current_user`."
                    ),
                    tags=["security", "idor", "authorization"],
                )
            )

        return findings

from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, StaleCommentConfig
from slopcheck.rules.generic.stale_comment import StaleCommentRule


def _make_config(enabled: bool = True) -> AppConfig:
    config = AppConfig()
    config.rules.stale_comment = StaleCommentConfig(enabled=enabled)
    return config


def _scan(content: str, path: str = "src/util.py", enabled: bool = True) -> list:
    rule = StaleCommentRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(enabled=enabled),
    )


def test_detects_redundant_comment_python() -> None:
    # Comment restates the function call almost verbatim (>60% word overlap)
    code = "# initialize user session\ninitialize_user_session()\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "stale_comment"


def test_allows_explanatory_comment() -> None:
    # Comment explains WHY, not WHAT
    code = "# Use exponential backoff to avoid thundering herd problem\ntime.sleep(delay)\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_detects_redundant_comment_js() -> None:
    code = "// validate user email address\nvalidate_user_email_address(email);\n"
    findings = _scan(code, path="src/util.ts")
    assert len(findings) == 1


def test_skips_very_short_comment() -> None:
    # Less than 3 words in comment -- too short to judge
    code = "# ok\nx = 1\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_disabled_rule() -> None:
    code = "# initialize user session\ninitialize_user_session()\n"
    findings = _scan(code, enabled=False)
    assert len(findings) == 0


def test_comment_at_end_of_file_no_next_line() -> None:
    code = "x = 1\n# this is the last line\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_clean_explanatory_comment_python() -> None:
    # These words are mostly different between comment and code
    code = (
        "# Redis key expires after five minutes to prevent stale data\n"
        "redis.setex(key, 300, value)\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_ruby_extension() -> None:
    # Ruby .rb is not in the supported extensions, scan should return empty list
    rule = StaleCommentRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/code.rb",
        content="# initialize user session\ninitialize_user_session()\n",
        config=_make_config(),
    )
    assert findings == []

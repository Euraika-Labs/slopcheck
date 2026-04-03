from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, WithinFileDuplicationConfig
from slopcheck.rules.generic.within_file_duplication import WithinFileDuplicationRule


def _make_config(enabled: bool = True, min_lines: int = 4) -> AppConfig:
    config = AppConfig()
    config.rules.within_file_duplication = WithinFileDuplicationConfig(
        enabled=enabled, min_lines=min_lines
    )
    return config


def _scan(content: str, path: str = "src/util.py", min_lines: int = 4) -> list:
    rule = WithinFileDuplicationRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=_make_config(min_lines=min_lines),
    )


def _make_dup_block(n_lines: int = 5, padding: int = 3) -> str:
    block = "\n".join(f"x{i} = do_thing_{i}()" for i in range(n_lines))
    filler = "\n".join(f"y = {i}" for i in range(padding))
    return f"{block}\n{filler}\n{block}\n"


def test_detects_duplicate_block() -> None:
    code = _make_dup_block()
    findings = _scan(code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "within_file_duplication"


def test_allows_no_duplication() -> None:
    code = "\n".join(f"x{i} = {i}" for i in range(20))
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = WithinFileDuplicationRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="template.html",
        content=_make_dup_block(),
        config=_make_config(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    rule = WithinFileDuplicationRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/util.py",
        content=_make_dup_block(),
        config=_make_config(enabled=False),
    )
    assert len(findings) == 0


def test_custom_min_lines() -> None:
    # With min_lines=8, a 5-line duplicate should not trigger
    code = _make_dup_block(n_lines=5)
    findings = _scan(code, min_lines=8)
    assert len(findings) == 0


def test_detects_in_ts_file() -> None:
    code = _make_dup_block()
    findings = _scan(code, path="src/util.ts")
    assert len(findings) >= 1


def test_file_too_short_for_two_windows() -> None:
    code = "a = 1\nb = 2\nc = 3\n"
    findings = _scan(code)
    assert len(findings) == 0

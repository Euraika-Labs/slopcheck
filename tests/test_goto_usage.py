from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, GotoUsageConfig
from slopcheck.rules.generic.goto_usage import GotoUsageRule


def _scan(content: str, path: str = "src/main.go") -> list:
    rule = GotoUsageRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_goto_in_go() -> None:
    code = "func main() {\ngoto cleanup\ncleanup:\n}\n"
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "goto_usage"


def test_detects_goto_in_c() -> None:
    code = "int main() {\n    goto end;\nend:\n    return 0;\n}\n"
    findings = _scan(code, path="src/main.c")
    assert len(findings) == 1


def test_detects_goto_indented() -> None:
    code = "    goto retry;\n"
    findings = _scan(code)
    assert len(findings) == 1


def test_skips_comment_line() -> None:
    code = "// goto cleanup\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_label_definition() -> None:
    # Labels are not goto statements
    code = "cleanup:\n"
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_unsupported_extension() -> None:
    rule = GotoUsageRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/app.py",
        content="goto label\n",
        config=AppConfig(),
    )
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.goto_usage = GotoUsageConfig(enabled=False)
    rule = GotoUsageRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/main.go",
        content="goto cleanup\n",
        config=config,
    )
    assert len(findings) == 0


def test_clean_code_no_findings() -> None:
    code = "func main() {\n    defer cleanup()\n}\n"
    findings = _scan(code)
    assert len(findings) == 0

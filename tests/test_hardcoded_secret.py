from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, HardcodedSecretConfig
from slopcheck.rules.generic.hardcoded_secret import HardcodedSecretRule


def _scan(content: str, path: str = "src/config.py") -> list:
    rule = HardcodedSecretRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


def test_detects_password_assignment() -> None:
    findings = _scan('password = "supersecretpassword123"\n')
    assert len(findings) == 1
    assert "password" in findings[0].message.lower()


def test_detects_api_key() -> None:
    findings = _scan('api_key = "production-key-value-abc123"\n')
    assert len(findings) == 1


def test_detects_secret_key() -> None:
    findings = _scan('SECRET_KEY = "django-insecure-xyz987654"\n')
    assert len(findings) == 1


def test_detects_access_token() -> None:
    findings = _scan('access_token = "ghp_realtoken12345"\n')
    assert len(findings) == 1


def test_skips_placeholder_your_password() -> None:
    findings = _scan('password = "your-password-here"\n')
    assert len(findings) == 0


def test_skips_placeholder_replace() -> None:
    findings = _scan('api_key = "REPLACE_WITH_YOUR_KEY"\n')
    assert len(findings) == 0


def test_skips_placeholder_example() -> None:
    findings = _scan('secret_key = "example_secret"\n')
    assert len(findings) == 0


def test_skips_test_files() -> None:
    findings = _scan('password = "realpassword123"\n', path="tests/test_auth.py")
    assert len(findings) == 0


def test_skips_fixture_files() -> None:
    findings = _scan('password = "realpassword123"\n', path="tests/fixtures/users.py")
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.hardcoded_secret = HardcodedSecretConfig(enabled=False)
    rule = HardcodedSecretRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="src/config.py",
        content='password = "supersecretpassword123"\n',
        config=config,
    )
    assert len(findings) == 0


def test_high_entropy_value_high_confidence() -> None:
    findings = _scan('api_key = "kR3mN8pQ2vX7wL4jB6sY1uZ9"\n')
    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_low_entropy_value_medium_confidence() -> None:
    # A short, low-entropy value (all same chars) gets MEDIUM confidence
    findings = _scan('password = "aaaaaaaaaa"\n')
    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"

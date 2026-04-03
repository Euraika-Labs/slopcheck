from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, ThreadUnsafeGlobalConfig
from slopcheck.rules.generic.thread_unsafe_global import ThreadUnsafeGlobalRule


def _scan(content: str, path: str = "worker.py") -> list:
    rule = ThreadUnsafeGlobalRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


# ── Positive cases ────────────────────────────────────────────────────────────

def test_module_level_list_with_threading_import() -> None:
    code = (
        "import threading\n"
        "\n"
        "cache = []\n"
        "\n"
        "def worker():\n"
        "    cache.append(1)\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "cache" in findings[0].message


def test_module_level_dict_with_asyncio_import() -> None:
    code = (
        "import asyncio\n"
        "\n"
        "state = {}\n"
        "\n"
        "async def handler():\n"
        "    state['key'] = 1\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "state" in findings[0].message


def test_module_level_mutable_with_concurrent_futures() -> None:
    code = (
        "from concurrent.futures import ThreadPoolExecutor\n"
        "\n"
        "results = []\n"
    )
    findings = _scan(code)
    assert len(findings) == 1


def test_multiple_mutables_flagged() -> None:
    code = (
        "import threading\n"
        "\n"
        "queue = []\n"
        "registry = {}\n"
    )
    findings = _scan(code)
    assert len(findings) == 2


# ── Negative cases ────────────────────────────────────────────────────────────

def test_no_threading_import_not_flagged() -> None:
    """Module-level mutable without any threading usage — not flagged."""
    code = (
        "cache = []\n"
        "\n"
        "def process():\n"
        "    cache.append(1)\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_allcaps_constant_not_flagged() -> None:
    code = (
        "import threading\n"
        "\n"
        "ALLOWED_HOSTS = []\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_dunder_not_flagged() -> None:
    code = (
        "import threading\n"
        "\n"
        "__all__ = []\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_logger_not_flagged() -> None:
    code = (
        "import threading\n"
        "import logging\n"
        "\n"
        "logger = logging.getLogger(__name__)\n"
        "data = []\n"
    )
    findings = _scan(code)
    # only data should be flagged, not logger (logger is not a [] or {} assignment)
    assert all("data" in f.message for f in findings)


def test_indented_mutable_not_flagged() -> None:
    """List inside a function body should not be flagged."""
    code = (
        "import threading\n"
        "\n"
        "def setup():\n"
        "    local = []\n"
        "    return local\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_non_python_file() -> None:
    code = (
        "import threading\n"
        "cache = []\n"
    )
    findings = _scan(code, path="worker.go")
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.thread_unsafe_global = ThreadUnsafeGlobalConfig(enabled=False)
    rule = ThreadUnsafeGlobalRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="worker.py",
        content="import threading\ncache = []\n",
        config=config,
    )
    assert len(findings) == 0


def test_severity_and_confidence() -> None:
    code = (
        "import threading\n"
        "\n"
        "cache = []\n"
    )
    findings = _scan(code)
    assert findings[0].severity.value == "warning"
    assert findings[0].confidence.value == "medium"

from pathlib import Path

from slopcheck.config import AppConfig, RedundantSqlIndexConfig, RulesConfig
from slopcheck.rules.generic.redundant_sql_index import RedundantSqlIndexRule


def _scan(content: str, path: str = "schema.sql", enabled: bool = True) -> list:
    rule = RedundantSqlIndexRule()
    config = AppConfig(
        rules=RulesConfig(
            redundant_sql_index=RedundantSqlIndexConfig(enabled=enabled),
        )
    )
    return rule.scan_file(
        repo_root=Path("."),
        relative_path=path,
        content=content,
        config=config,
    )


# ---------------------------------------------------------------------------
# Positive cases — should fire
# ---------------------------------------------------------------------------

_REDUNDANT_BASIC = """\
CREATE INDEX idx_user_id ON users (id);
CREATE INDEX idx_user_id_email ON users (id, email);
"""


def test_prefix_index_flagged() -> None:
    findings = _scan(_REDUNDANT_BASIC)
    assert len(findings) == 1
    assert findings[0].rule_id == "redundant_sql_index"
    # idx_user_id (id) is a prefix of idx_user_id_email (id, email)
    assert "idx_user_id" in findings[0].message


def test_prefix_index_line_number() -> None:
    findings = _scan(_REDUNDANT_BASIC)
    assert findings[0].location.line == 1


def test_unique_index_also_detected() -> None:
    sql = """\
CREATE UNIQUE INDEX uk_name ON orders (customer_id);
CREATE INDEX idx_order_full ON orders (customer_id, created_at);
"""
    findings = _scan(sql)
    assert len(findings) == 1
    assert "uk_name" in findings[0].message


def test_three_index_chain() -> None:
    """idx_a (x) is prefix of idx_b (x,y), which is prefix of idx_c (x,y,z)."""
    sql = """\
CREATE INDEX idx_a ON t (x);
CREATE INDEX idx_b ON t (x, y);
CREATE INDEX idx_c ON t (x, y, z);
"""
    findings = _scan(sql)
    # At least idx_a is redundant; idx_b may also be reported.
    assert len(findings) >= 1
    names_in_messages = " ".join(f.message for f in findings)
    assert "idx_a" in names_in_messages


# ---------------------------------------------------------------------------
# Negative cases — should NOT fire
# ---------------------------------------------------------------------------

_NON_REDUNDANT = """\
CREATE INDEX idx_a ON t (col_a);
CREATE INDEX idx_b ON t (col_b);
"""


def test_non_overlapping_indexes_ok() -> None:
    findings = _scan(_NON_REDUNDANT)
    assert findings == []


def test_same_columns_different_order_ok() -> None:
    """Different column order is not a prefix — should not fire."""
    sql = """\
CREATE INDEX idx_a ON t (a, b);
CREATE INDEX idx_b ON t (b, a);
"""
    findings = _scan(sql)
    assert findings == []


def test_single_index_ok() -> None:
    sql = "CREATE INDEX idx_a ON t (a);\n"
    findings = _scan(sql)
    assert findings == []


def test_indexes_on_different_tables_ok() -> None:
    sql = """\
CREATE INDEX idx_a ON table_a (id);
CREATE INDEX idx_b ON table_b (id, name);
"""
    findings = _scan(sql)
    assert findings == []


def test_disabled_returns_nothing() -> None:
    findings = _scan(_REDUNDANT_BASIC, enabled=False)
    assert findings == []


def test_unsupported_extension_ignored() -> None:
    rule = RedundantSqlIndexRule()
    findings = rule.scan_file(
        repo_root=Path("."),
        relative_path="migration.py",
        content=_REDUNDANT_BASIC,
        config=AppConfig(),
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Metadata checks
# ---------------------------------------------------------------------------


def test_severity_and_confidence() -> None:
    findings = _scan(_REDUNDANT_BASIC)
    assert findings[0].severity.value == "note"
    assert findings[0].confidence.value == "high"


def test_tags_include_sql() -> None:
    findings = _scan(_REDUNDANT_BASIC)
    assert "sql" in findings[0].tags
    assert "database" in findings[0].tags

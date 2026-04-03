from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from slopcheck.config import AppConfig
from slopcheck.models import Confidence, Finding, Severity
from slopcheck.rules.base import Rule

# Matches: CREATE [UNIQUE] INDEX <name> ON <table> (<col1>, <col2>, ...)
_INDEX_RE = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(\w+)\s+ON\s+(\w+)\s*\(([^)]+)\)",
    re.IGNORECASE,
)


def _parse_columns(cols_str: str) -> list[str]:
    """Return a lower-cased, stripped list of column names from a column list string."""
    return [c.strip().lower() for c in cols_str.split(",") if c.strip()]


def _is_prefix(shorter: list[str], longer: list[str]) -> bool:
    """Return True if `shorter` is a non-empty prefix of `longer`."""
    if not shorter or len(shorter) >= len(longer):
        return False
    return longer[: len(shorter)] == shorter


class RedundantSqlIndexRule(Rule):
    rule_id = "redundant_sql_index"
    title = "Redundant SQL index detected"
    # .sql files only — deliberately NOT using DEFAULT_CODE_EXTENSIONS
    supported_extensions = {".sql"}

    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        rule_config = config.rules.redundant_sql_index
        if not rule_config.enabled or not self.applies_to_path(relative_path):
            return []

        # Collect all index definitions: table -> list of (index_name, columns, lineno)
        table_indexes: dict[str, list[tuple[str, list[str], int]]] = defaultdict(list)

        for lineno, line in enumerate(content.splitlines(), start=1):
            m = _INDEX_RE.search(line)
            if m:
                index_name = m.group(1)
                table_name = m.group(2).lower()
                columns = _parse_columns(m.group(3))
                if columns:
                    table_indexes[table_name].append((index_name, columns, lineno))

        findings: list[Finding] = []

        for table, indexes in table_indexes.items():
            # For every pair, check if one's columns are a prefix of another's.
            for _i, (name_a, cols_a, lineno_a) in enumerate(indexes):
                for name_b, cols_b, _lineno_b in indexes:
                    if name_a == name_b:
                        continue
                    # cols_a is a prefix of cols_b → index_a is made redundant by index_b
                    if _is_prefix(cols_a, cols_b):
                        evidence = (
                            f"INDEX {name_a} ON {table}({', '.join(cols_a)}) "
                            f"is a prefix of INDEX {name_b}({', '.join(cols_b)})"
                        )
                        findings.append(
                            self.build_finding(
                                relative_path=relative_path,
                                line=lineno_a,
                                message=(
                                    f"Index `{name_a}` on table `{table}` covers "
                                    f"({', '.join(cols_a)}), which is a leading prefix of "
                                    f"`{name_b}` ({', '.join(cols_b)}). "
                                    "The shorter index is redundant."
                                ),
                                severity=Severity.NOTE,
                                confidence=Confidence.HIGH,
                                evidence=evidence,
                                suggestion=(
                                    f"Drop index `{name_a}` — queries that would use it "
                                    f"can already use `{name_b}`."
                                ),
                                tags=["sql", "performance", "database"],
                            )
                        )
                        # Report each redundant index once.
                        break

        return findings

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class BaselineFile(BaseModel):
    version: int = 1
    fingerprints: list[str] = Field(default_factory=list)


def load_baseline(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()

    try:
        baseline = BaselineFile.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"slopcheck: invalid baseline file {path}: {exc}") from None
    return set(baseline.fingerprints)


def write_baseline(path: Path, fingerprints: list[str]) -> None:
    if ".." in str(path):
        raise Exception("Invalid file path")
    baseline = BaselineFile(fingerprints=sorted(set(fingerprints)))
    path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")

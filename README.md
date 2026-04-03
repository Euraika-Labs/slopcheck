# ai-slopcheck

[![PyPI](https://img.shields.io/pypi/v/ai-slopcheck?color=blue)](https://pypi.org/project/ai-slopcheck/)
[![Python](https://img.shields.io/pypi/pyversions/ai-slopcheck)](https://pypi.org/project/ai-slopcheck/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-793%20passing-brightgreen)]()
[![Rules](https://img.shields.io/badge/rules-72-blue)]()

**Deterministic scanner for AI-style code failures. 72 rules. No LLM. No backend.**

> Catches the mistakes AI coding assistants leave behind — stub functions, silent error handling, hallucinated placeholders, hardcoded secrets, and 68 more patterns across Python, JS/TS, Go, C/C++, SQL, and Markdown.

---

## Install

```bash
pip install ai-slopcheck
```

## Quick Start

```bash
# Scan a project
slopcheck scan . --output findings.json --fail-on warning

# View results
slopcheck summary findings.json

# GitHub Security tab (SARIF)
slopcheck sarif findings.json

# Only scan changed files (CI)
slopcheck scan . --changed-files git --fail-on warning
```

## What It Catches

| Category | Rules | Examples |
|----------|:-----:|---------|
| **AI Detection** | 15 | Stub functions, instruction comments, conversational bleed, identity refusals |
| **Security** | 7 | Hardcoded secrets, SQL injection, XSS, weak hashing, obfuscated code |
| **JavaScript / Node** | 11 | await-in-loop, unguarded JSON.parse, loose equality, React antipatterns |
| **Go** | 3 | Ignored errors, missing defer, wrong error wrapping |
| **Python** | 1 | Mutable default arguments |
| **Cross-Language** | 17 | Debug code, unreachable code, deep inheritance, dangerous shell in markdown |
| **Data-Flow** | 4 | Contradictory null checks, lock safety, IDOR risk, thread-unsafe globals |
| **Quality** | 9 | Deep nesting, large functions, duplication (opt-in) |
| **API Contract** | 1 | Removed routes, deprecated endpoints |
| **Repo-Specific** | 1 | Import boundary violations |
| **Meta** | 1 | Unused suppression directives |

## Features

- **72 deterministic rules** — no LLM, no network, no randomness
- **6 languages** — Python, JS/TS, Go, C/C++, SQL, Markdown
- **Inline suppression** — `# slopcheck: ignore[rule_id]`
- **SARIF output** — integrates with GitHub Security tab
- **Diff-only mode** — scan only changed files (`--changed-files git`)
- **Baselines** — suppress existing findings, fail only on new ones
- **API snapshots** — detect removed API routes
- **Tree-sitter** — optional AST context for better precision
- **Threaded** — multi-core scanning (`--jobs N`)
- **Confidence filtering** — `--min-confidence medium` for high-signal-only mode

## GitHub Actions

```yaml
name: slopcheck
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install ai-slopcheck
      - run: slopcheck scan . --output findings.json --fail-on warning
      - run: slopcheck github-annotations findings.json
      - run: slopcheck sarif findings.json > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

## Baselines (Incremental Adoption)

```bash
# First run: baseline existing findings
slopcheck scan . --output findings.json --fail-on none
slopcheck create-baseline findings.json

# CI: only fail on NEW findings
slopcheck scan . --baseline .slopcheck/baseline.json --fail-on warning
```

## CLI Reference

| Command | Purpose |
|---------|---------|
| `slopcheck scan [paths]` | Scan files, write findings JSON |
| `slopcheck summary <file>` | Markdown summary |
| `slopcheck github-annotations <file>` | GitHub workflow annotations |
| `slopcheck sarif <file>` | SARIF v2.1.0 output |
| `slopcheck create-baseline <file>` | Create fingerprint baseline |
| `slopcheck api-snapshot` | Snapshot API routes for contract checks |

### Key `scan` Options

| Option | Default | Description |
|--------|---------|-------------|
| `--fail-on` | `error` | Exit 1 at severity: `none` / `note` / `warning` / `error` |
| `--min-confidence` | `low` | Filter: `low` / `medium` / `high` |
| `--baseline` | — | Suppress fingerprints from baseline file |
| `--changed-files` | — | `git` or `@file.txt` for diff-only mode |
| `--jobs` | auto | Thread count (0=auto, 1=sequential) |
| `--api-baseline` | — | API snapshot for contract comparison |

## Configuration

Create `.slopcheck/config.yaml`:

```yaml
rules:
  # Disable a rule
  js_loose_equality:
    enabled: false
  
  # Enable an opt-in rule with custom threshold
  deep_nesting:
    enabled: true
    max_depth: 5
  
  # Configure detection
  hallucinated_placeholder:
    allowed_domains: ["example.com", "localhost"]
```

## Tree-sitter (Optional)

For better precision (~5% improvement on string/comment context detection):

```bash
pip install ai-slopcheck[ast]
# Or manually:
pip install tree-sitter-python tree-sitter-javascript tree-sitter-go tree-sitter-typescript
```

## Project Layout

```
slopcheck/
├── cli.py                 — 6 CLI commands
├── config.py              — 50+ Pydantic config models
├── models.py              — Finding, ScanResult (stable contract)
├── engine/
│   ├── scanner.py         — Threaded orchestrator
│   ├── suppression.py     — Inline ignore parser
│   └── context_filter.py  — String/comment detector
├── parsers/
│   └── treesitter.py      — Optional AST adapter
├── rules/
│   ├── generic/           — 71 cross-repo rules
│   └── repo/              — 1 architecture rule
├── output/
│   ├── sarif.py           — SARIF v2.1.0
│   ├── annotations.py     — GitHub annotations
│   └── markdown_summary.py
└── state/
    └── store.py           — Baseline persistence
```

## Documentation

| Document | Content |
|----------|---------|
| [Architecture](docs/architecture.md) | Runtime model, data model, threading, rule tables |
| [Rule Catalog](docs/rule-catalog.md) | All 72 rules with examples and FP notes |
| [Rule Authoring](docs/rule-authoring.md) | How to add new rules |
| [Configuration](docs/configuration-guide.md) | All config options |
| [CLI Reference](docs/cli-reference.md) | Commands and flags |
| [User Guide](docs/user-guide.md) | Getting started, CI setup |
| [Security Model](docs/security-model.md) | Threat model, safety |
| [Wiki](https://github.com/Euraika-Labs/slopcheck/wiki) | FAQ, tutorials |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Quick summary:

1. Branch from `develop`
2. Add rule + config + tests
3. `pytest && ruff check .`
4. Merge request

## License

[MIT](LICENSE) — Euraika 2026

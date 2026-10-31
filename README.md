# pkgtruth

**What you review isn't always what you install.**

pkgtruth compares a Python wheel against explicitly selected local source and turns byte differences into inspectable evidence. One deterministic engine powers an installable CLI and a responsive FastAPI web application. Built by **Commit-tee** for Hacktoberfest 2026, Problem 4: Published Package vs Source Code Integrity Analyzer.

## Working today — milestone 1

- Virtual wheel/source ZIP inspection with bounded decompression, path/link/collision protections; no target execution.
- Source-directory comparison in the CLI, and explicit source-prefix mapping in both interfaces.
- Added, removed, modified and identical files; SHA-256 hashes; stable evidence IDs; bounded text diffs and binary handling.
- Uploads, real investigation results, searchable/filterable file explorer, local SQLite report history, JSON download.
- Versioned Pydantic reports and deterministic offline security/interface tests.

No PyPI retrieval, RECORD/provenance verification, behavioral analysis, policy evaluation, watchlists or AI inference yet. A matching comparison does **not** prove safety. `COMPLETE` describes supported byte-comparison coverage only. See [roadmap](docs/ROADMAP.md).

## Install and launch

```sh
python3 -m venv .venv  # Python 3.12+
. .venv/bin/activate
pip install -e '.[test]'
python examples/generate.py
pkgtruth serve --port 8000
```

Open **http://127.0.0.1:8000**. Start an investigation using `examples/clean.whl` or `examples/tampered.whl` and `examples/source.zip`. Leave source prefix blank. Results contain only real analysis data.

This is local, single-user software. Do not expose it publicly or behind a proxy. Reports include source excerpts and persist in `.pkgtruth/` (override with `PKGTRUTH_DATA_DIR`). No raw uploads are retained.

## CLI

```sh
pkgtruth --help
pkgtruth scan local --wheel examples/clean.whl --source examples/source
pkgtruth scan local --wheel examples/tampered.whl --source examples/source.zip --json --output report.json
pkgtruth scan local --wheel examples/clean.whl --source /path/to/repo --source-prefix src
pkgtruth report <scan-id> --output exported.json
```

Exit codes: **0** = complete comparison with no unexplained differences (informational packaging differences may remain); **1** = review required due to unexplained differences or partial mapping; **2** = invalid arguments, rejected input or operational error. JSON scan output goes exclusively to stdout, errors to stderr. Exit 0 is not a security approval.

Source prefix is exact, relative and case-sensitive: use `project-1.0/src` when a ZIP contains `project-1.0/src/demo/__init__.py` and the wheel contains `demo/__init__.py`. No source layout is guessed. Source files outside the prefix are excluded and counted; source-only files inside it are reported as removed. Wheel `.data` relocation is unsupported and marked PARTIAL. No shared paths also produces PARTIAL.

Only the commands shown above are supported. PyPI, DNA, watch and policy commands belong to future milestones.

## Reports and architecture

`inputs.py` safely reads untrusted inputs; `analysis.py` is the single comparison service; `models.py` defines schema **1.0**; `storage.py` persists reports; `cli.py` and `web.py` are thin interfaces. Templates, CSS and vanilla JS ship in the Python wheel, with no Node build or external CDN assets.

JSON includes artifact and source-tree hashes, explicit mappings, all file differences, stable evidence and finding references, coverage, limitations, and explicit statuses for unimplemented checks. See [report contract](docs/REPORT_SCHEMA.md) and [actual example inputs/outputs](examples/README.md). Packaging metadata is informational by filename convention, not verified legitimate. Text previews may truncate; hashes cover full inspected bytes.

Routes: `GET /`, `GET /scans/new`, `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/report.json`, `GET /health`. Interactive docs are disabled; the report contract is published as a schema file.

## Tests

```sh
pip install -e '.[test]'
python -m pytest -q
pkgtruth --help
python -m build
```

CI installs the built wheel in a clean environment and runs tests from outside the repository, including web/CLI equivalence, multipart uploads, escaping, report exports, unsafe paths/links, collisions and resource limits. It needs no network services during tests. Actual local commands/results and remote CI status are recorded in [test evidence](docs/TEST_EVIDENCE.md).

## AI and deployment status

**Product models: none.** Ollama and `qwen3.5:4b` are planned; genuine inference, structured-output validation, digest/license recording and evidence grounding remain unverified. Codex helped implement this milestone; PRs disclose coding assistance separately from runtime AI.

[Deployment instructions](docs/DEPLOYMENT.md) describe the loopback-only boundary and remaining production checks. [Engineering decisions](docs/DECISIONS.md) document trade-offs and limits. MIT licensed. No public production-readiness claim.

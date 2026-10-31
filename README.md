# pkgtruth

**What you review isn't always what you install.**

pkgtruth investigates Python wheels against selected source and prior artifacts. One shared Python engine powers a browser application and CLI. Built by **Commit-tee** for Hacktoberfest 2026, Problem 4: Published Package vs Source Code Integrity Analyzer.

## Working features

- Local wheel/source comparison and exact-name PyPI lookup with exact-version scans, bounded downloads and registry SHA-256 verification.
- Conservative GitHub release correspondence, file hashes/diffs, wheel RECORD checks, startup hooks, bounded AST capabilities and static dependency/entry-point comparisons.
- Real private Ollama **qwen3.5:4b** explanations of selected evidence. Structured responses must cite offered evidence IDs. Model output cannot change deterministic facts or adoption policies.
- **Release DNA:** compare stored artifacts or two exact PyPI releases for changed files, imports, declarations and first-observed capabilities, relative to that baseline.
- **Install Impact Preview:** conditional startup/module/entry-point relationships backed by static evidence.
- **Proof Capsule:** downloadable JSON and standalone escaped HTML with findings, hashes, model details, history, coverage and uncertainty.
- **Release Gate:** configurable deterministic ALLOW / REVIEW / BLOCK, with policy rules and evidence references.
- Manual latest-release watchlist, duplicate-suppressed observations, local scan history, bounded background PyPI/AI jobs and real status polling. Interrupted jobs require resubmission.

No investigated code is installed, imported, built or executed. Valid RECORD means internal consistency; registry hashes identify downloaded bytes. Neither authenticates source or establishes package safety. GitHub correspondence is **unverified**, provenance remains NOT_CHECKED, and limited inspection is PARTIAL. AI explanations are unverified hypotheses, not verdicts.

## Install and launch

```sh
python3 -m venv .venv  # Python 3.12+
. .venv/bin/activate
pip install -e '.[test]'
python examples/generate.py
pkgtruth serve --port 8000
```

Open http://127.0.0.1:8000 directly in a normal browser. Upload `examples/startup.whl` and `examples/source.zip` with blank source prefix, or look up `idna` and investigate version `3.10`. Use clean and startup fixture reports as the DNA baseline/current snapshots. Results include real file diffs and evidence; the AI button submits a private local inference job.

This is loopback-only, single-user software. Reports include source excerpts and persist in `.pkgtruth/` (override `PKGTRUTH_DATA_DIR`). Raw uploads/downloads are not retained. Do not expose the application or Ollama publicly. Embedded browsers that send `Origin: null` are intentionally denied mutations.

## CLI

```sh
pkgtruth scan local --wheel examples/clean.whl --source examples/source.zip --json
pkgtruth scan pypi --name idna --version 3.10 --json --output report.json
pkgtruth scan local --wheel examples/startup.whl --source examples/source.zip --ai --json
pkgtruth investigate <scan-id> --json
pkgtruth dna idna --previous 3.9 --current 3.10 --json
pkgtruth dna --previous <baseline-scan-id> --current <current-scan-id> --json
pkgtruth report <scan-id> --format html --output capsule.html
pkgtruth policy check --report report.json --json
pkgtruth watch --add idna --json
pkgtruth watch --once --scan-new --json
pkgtruth watch --remove idna
```

Scan/DNA exits: **0** complete supported inspection and configured policy ALLOW; **1** review/block, partial coverage or requested AI unavailable; **2** invalid input/operation error. `policy check` exits **0 ALLOW / 1 REVIEW / 2 BLOCK / 3 error**. `investigate` exits 0 only for validated AI output; export/watch success means the operation completed, not package approval. JSON output goes to stdout and errors to stderr. Exit 0 and ALLOW never guarantee safety.

CLI local source directories and ZIPs use an exact case-sensitive `--source-prefix`, e.g. `release/src`. PyPI resolution supports a unique overlapping root or `src` layout at an exact version tag/commit; unsupported or ambiguous correspondence yields artifact-only PARTIAL coverage. Wheels only; no source-distribution build fallback. Watch checks registry metadata manually; `--scan-new` additionally investigates a new/changed snapshot. No autonomous scheduler or alert delivery is claimed.

## Private Qwen

The default API is `http://127.0.0.1:11434`. `PKGTRUTH_OLLAMA_URL` permits only documented private host spellings, not arbitrary public endpoints. The model tag must match the pinned digest in [HACKATHON.md](HACKATHON.md). Generation requests structured JSON with context 4096, output 1024, temperature 0 and thinking disabled. Missing model, digest mismatch, schema failure and unknown evidence references produce explicit statuses while preserving deterministic results. Actual CLI and web inference was verified; CI uses deterministic mocks.

## Reports, tests and deployment

`analysis.py` and `security.py` provide the shared static engine; adapters in `pypi.py`, `investigator.py`, `dna.py`, `impact.py`, `policy.py`, `watch.py` and `capsule.py` enrich the same report. `storage.py` uses SQLite and `jobs.py` a bounded single-process worker. Templates/CSS/vanilla JS ship in the Python wheel, without a Node build or CDN.

```sh
python -m pytest -q
python -m build
python examples/generate.py
git diff --exit-code -- examples docs/report.schema.json
```

Existing CI builds and installs the actual wheel, tests it outside the checkout, validates CLI/web, then checks deterministic regeneration. No external PyPI/Ollama services are needed in CI. [Examples](examples/README.md), [report schema 1.2](docs/REPORT_SCHEMA.md), [test evidence](docs/TEST_EVIDENCE.md), [security limits](docs/SECURITY_RULES.md), [decisions](docs/DECISIONS.md) and [roadmap](docs/ROADMAP.md) document behavior and acceptance.

[Deployment](docs/DEPLOYMENT.md) includes Docker/Compose configuration and remaining operational blockers. Docker execution is unverified on this machine. Authentication, per-user authorization, PostgreSQL/migrations and isolated durable workers remain unimplemented; no secure public multi-user deployment is claimed. MIT licensed. Codex implementation assistance is disclosed separately from runtime Qwen.

# Roadmap

## Milestone 1 — local Web + CLI scanner

Branch: `feat/local-analysis`. PR: [#2](https://github.com/k3tan7/pkgtruth/pull/2). Review/merge gate: do not merge automatically.

Implemented and acceptance-tested locally (51 passing tests on Python 3.12.15 and 3.14.6):
- Installable Python package and one deterministic analysis service.
- Bounded virtual ZIP inspection and no-follow source-directory inspection.
- Explicit source prefix, SHA-256 comparisons, stable evidence IDs, versioned JSON reports.
- FastAPI upload form, results, searchable/filterable expandable file diffs, JSON download, local scan history.
- CLI local scan, JSON output, persisted report export, loopback server command.
- Offline clean/tampered fixtures, security and interface-equivalence tests, packaging CI.

Acceptance met: installed CLI and web generate equivalent reports for clean/tampered inputs; unsafe archives are rejected; packaged templates/static assets work. Real same-origin HTTP uploads and browser results/filtering are verified. Embedded-browser uploads send an opaque Origin and are rejected; mouse-driven upload in an external browser remains a manual check. GitHub CI passed for implementation commit `6303c91` ([run](https://github.com/k3tan7/pkgtruth/actions/runs/41232943558)). Human PR review and merge are pending; verify the current head checks before merging.

## Later milestones (not delivered)

2. RECORD validation, executable startup surfaces, AST indicators and false-positive tests.
3. Exact-version PyPI retrieval, network boundaries and conservative source revision resolution.
4. Real Ollama/Qwen inference with schema/evidence validation and recorded model/license/digest evidence.
5. Deterministic release DNA and interactive timeline.
6. Proof Capsule HTML export and deterministic policy configuration/evaluation.
7. Watchlists, durable background jobs, progress, monitoring and product completion.
8. Authentication, private-scan isolation, PostgreSQL/migrations, isolated workers, operational acceptance.

Milestone 1 deliberately has no PyPI search, model inference, behavioral detection, provenance verification, Release Gate or watchlist. Reports mark these checks explicitly unimplemented. Continue after milestone 1 PR review and merge.

## Event timing

Checked 2026-11-01 against [MLH event schedule](https://events.mlh.com/events/15017-hacktoberfest-hack-day-sonipat-x-rishihood-university).
The detailed schedule lists building from 6 PM to 6 AM and evaluation starting at 6 AM. No explicit submission freeze is published there, and the header displays CDT despite the Indian venue. Treat 6 AM on November 1 in the venue's local time as a conservative planning target, not a verified freeze. Preserve final testing time; organizer announcements remain authoritative.

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

Acceptance met: installed CLI and web generate equivalent reports for clean/tampered inputs; unsafe archives are rejected; packaged templates/static assets work. Real same-origin HTTP uploads and browser results/filtering are verified. Embedded-browser uploads send an opaque Origin and are rejected; mouse-driven upload in an external browser remains a manual check. GitHub CI passed for implementation commit `6303c91` ([run](https://github.com/k3tan7/pkgtruth/actions/runs/41232943558)). PR #2 was merged by the maintainer; milestone 1 is complete.

## Milestone 2 — security analysis

Branch: `codex/security-analysis`, based on safely fast-forwarded main after PR #2. PR: [#3](https://github.com/k3tan7/pkgtruth/pull/3).

Implemented and locally verified: 112 passing tests on Python 3.12.15 (installed wheel) and 3.14.6, plus four real localhost upload/export comparisons. GitHub Actions passed for implementation commit `b3684fe` ([run](https://github.com/k3tan7/pkgtruth/actions/runs/41235241675)). PR #3 was merged by the maintainer after final-head and main CI passed.
- RECORD hash/size/CSV coverage validation, explicit VALID/INVALID/UNAVAILABLE/UNRESOLVED states.
- Executable .pth and customization startup surfaces, bounded AST import/call indicators, native/bytecode inventory.
- Source-relative NEW/PRESENT/SOURCE_ONLY/UNKNOWN indicators with stable line-context evidence.
- Static entry-point/dependency changes against explicit in-scope declarations, without running build tools.
- Narrow generated-metadata classification, explicit parser limits and partial coverage.
- Shared CLI/web reports, RECORD/impact/metadata panels, schema 1.1 with legacy reading, offline security/false-positive regressions.

Acceptance met in offline fixtures and shared CLI/web integration tests: source tampering and new startup capabilities are detected with a rewritten valid RECORD; unchanged capabilities and known generated metadata remain informational. The maintainer merged this milestone; automatic merging remains prohibited.

## Consolidated integration — feat/package-intelligence

Based on merged main `dcaf3c1`. The consolidated request supersedes separate milestone PRs: one integration PR containing independently tested commits, followed by human review.

Implemented and offline tested (163 tests):

| Priority | Delivered functionality | Acceptance |
| --- | --- | --- |
| P0 | Exact-name/version PyPI, bounded download, digest/identity checks, claimed GitHub correspondence | Real idna 3.10 bytes verified; unsupported source/layout remains PARTIAL |
| P0 | Pinned private Qwen structured evidence investigator | Real CLI and HTTP web inference; schema/evidence/digest/failure regression tests |
| P0 | Deterministic Release DNA | Real idna 3.9 → 3.10: 12 artifact changes; stored-snapshot CLI/web comparison |
| P1 | Static Install Impact Preview | Conditional evidence-backed startup/module/entry-point edges; truncation explicit |
| P1 | JSON/HTML Proof Capsule | Escaped standalone actual report; deterministic DNA capsule example |
| P1 | Release Gate | Evidence-cited ALLOW/REVIEW/BLOCK, strict config, persisted settings; AI independent |
| P1 | Watchlist/history | Manual latest metadata checks, transactional duplicate suppression, optional changed-release scans |
| P1 | Background status | Bounded PyPI/AI queue, persisted actual status, INTERRUPTED on restart, retry by resubmission |
| Deployment | Private Linux Docker/Compose configuration and health check | Configuration supplied; Docker runtime unavailable and unverified |

Final wheel installation, real integrated workflows and final-head remote CI are recorded in TEST_EVIDENCE.md. Public multi-user production acceptance is **not complete**: authentication/authorization, per-user isolation, PostgreSQL/migrations, isolated durable workers, monitoring/alerts and operational restore/load tests remain deferred. This integration does not authenticate provenance, execute packages, infer proven runtime paths or use trained historical ML.

Stop at the single integration PR review boundary. Never merge automatically or bypass failing CI.

## Event timing

Checked 2026-11-01 against [MLH event schedule](https://events.mlh.com/events/15017-hacktoberfest-hack-day-sonipat-x-rishihood-university).
The detailed schedule lists building from 6 PM to 6 AM and evaluation starting at 6 AM. No explicit submission freeze is published there, and the header displays CDT despite the Indian venue. Treat 6 AM on November 1 in the venue's local time as a conservative planning target, not a verified freeze. Preserve final testing time; organizer announcements remain authoritative.

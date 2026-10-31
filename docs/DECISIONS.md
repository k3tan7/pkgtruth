# Decisions

## One engine, explicit scope

`analysis.analyze` accepts wheel bytes plus source ZIP bytes or a directory Path. Both interfaces call it and use the same Pydantic report. Paths are mapped only relative to the exact user-specified source prefix; no heuristic silently chooses between src layouts or archive wrappers. No common paths and wheel .data relocation produce PARTIAL coverage. Files outside the selected source prefix are counted as excluded.

COMPLETE means complete supported static inspection in the selected scope, not a full security investigation. Provenance is NOT_CHECKED, AI is NOT_CONFIGURED, and policy_decision is null. RECORD consistency is now checked separately; missing/invalid/unsupported RECORD and unsupported static parsers make analysis PARTIAL. Packaging metadata is informational by path only. Differences are review evidence, not malware verdicts. Source-only files are reported as removed, including files a legitimate build may intentionally omit.

## Conservative input boundary

ZIP members stay in memory; nothing is extracted. Limits: 16 MiB compressed per archive, 20 MiB expanded, 2 MiB per file, 1,000 entries, maximum 200:1 compression ratio, 512-character paths, 10 seconds per input-reader stage and a 30-second cumulative analysis deadline (checked between bounded operations). Reject links, special files, encryption, unsupported compression, duplicate names, Unicode/case aliases, path traversal and file/directory collisions. Very compressible legitimate files may be rejected intentionally.

Source directories are walked using descriptor-relative no-follow reads; symlinks and hardlinks are rejected. Local inputs should remain unchanged during inspection. These are cooperative resource limits, not process isolation or a hard real-time timeout. Production needs isolated workers with OS resource limits.

Text previews are at most 2,048 characters per side before diff computation. Hashes cover full inspected content, including binary files. Evidence IDs depend on path and both content hashes; scan IDs also include the rule version, full source-tree hash, artifact hash and selected prefix. ZIP container timestamps affect artifact identity. Report JSON is versioned and validated, with unknown fields rejected.

## Local web execution and persistence

FastAPI/Jinja2, responsive CSS, native multipart forms and minimal vanilla JavaScript avoid a Node build. Current interactions need no HTMX dependency. Accessible native details elements provide progressive file exploration. Upload state says work is underway without invented percentage progress.

One bounded scan runs in a thread pool per application process. The upload request remains open; this is a deliberate local milestone limitation, not a production durable-job design. Additional concurrent local scans receive 429. SQLite stores validated report JSON with parameterized queries; raw uploaded archives are not retained. No claim of PostgreSQL portability or production worker readiness is made.

Default bind is 127.0.0.1, hosts are restricted, and non-loopback HTTP clients are rejected. Cross-origin uploads are rejected, forms require a same-site double-submit token, uploads are bounded before multipart parsing, and HTML uses escaping plus CSP. Do not proxy the service or expose it publicly: it has no authentication or multi-user isolation. Report exports can include sensitive code excerpts.

## Runtime AI

No product AI model is used in milestone 1. The installed Qwen model described in the brief is a candidate for milestone 4, not verified application integration. Prior README/model declarations are corrected to reflect this distinction.

## Milestone 2 — static inspection without execution

Security checks live in security.py and run only through analysis.analyze. RECORD consistency is not provenance. A valid rewritten RECORD cannot hide independent source differences or introduced startup/capability indicators. We accept legacy signature-file exclusions without verifying signatures.

AST parsing has explicit byte/node/indicator limits. Rules report syntactic references, with alias resolution but no reachability or binding proof. Unchanged capabilities are informational; newly introduced startup directives/modules are high priority. Static metadata comparisons stay within the explicit source scope, use exact-path or unambiguous single declarations, and never execute build metadata. Unknown baselines remain visible. Generated metadata classification is narrowed to recognized names, and known source-only root build configuration is informational with explicit uncertainty; arbitrary code under .dist-info is not exempted.

Schema 1.1 extends 1.0 while retaining legacy report reading. Tool/rule versions and scan IDs change, preserving old stored results as originally analyzed. The Install impact preview is a structured evidence explorer; no call graph or runtime execution path is invented. See SECURITY_RULES.md for limitations and authoritative references.

## Consolidated package intelligence

- Preserve the installed-wheel CI and shared engine. PyPI is an adapter, never a target build/install; require registry byte digest, declared size and matching wheel identity before analysis.
- Restrict public fetches to PyPI/files.pythonhosted.org/api.github.com/codeload.github.com, validate public DNS and every bounded redirect, reject credentials/private destinations/encoded bodies. Exact GitHub tags resolve to commits; when the unauthenticated API quota is exhausted, git-archive ZIP commit comments provide unverified correspondence. Unsupported layouts or tags are artifact-only PARTIAL, never a default-branch substitution.
- Pin local Qwen by digest, inspect real runtime/license metadata and validate structured evidence citations. Context is a bounded selection, not full-repository understanding. Model text is an unverified explanation layer; deep-copy facts and policy. Test failures with mocks and verify genuine inference separately.
- DNA is deterministic comparison to a specified artifact, including bounded imports/declarations and capability evidence. A same-version snapshot comparison is permitted and labeled honestly; file changes alone are informational, and incomplete historical coverage remains explicit. No trained ML model.
- Policies rely only on deterministic facts and cite evidence. VALID RECORD cannot authenticate a publisher; ALLOW means configured supported checks only. Policy settings affect new scans; stored reports preserve their evaluation configuration.
- Keep SQLite, a single thread worker and status polling. Pending work becomes INTERRUPTED after restart; one process owns the store. Watch checks are manual registry metadata snapshots with bounded history and transactional duplicate suppression. They do not establish that new bytes were inspected unless a scan actually ran.
- HTML capsules escape untrusted content and include the full JSON. Impact relationships use conditional static language. Neither exported reports nor graph edges claim cryptographic provenance or runtime reachability.
- Supply private Linux Docker configuration but disclose that Docker is unavailable here. Authentication, PostgreSQL, isolated durable workers and public deployment remain explicit deferred work, not nominal production completion.

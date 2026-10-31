# Decisions

## One engine, explicit scope

`analysis.analyze` accepts wheel bytes plus source ZIP bytes or a directory Path. Both interfaces call it and use the same Pydantic report. Paths are mapped only relative to the exact user-specified source prefix; no heuristic silently chooses between src layouts or archive wrappers. No common paths and wheel .data relocation produce PARTIAL coverage. Files outside the selected source prefix are counted as excluded.

COMPLETE means complete supported byte comparison in the selected scope, not a full security investigation. Provenance/RECORD are NOT_CHECKED, AI is NOT_CONFIGURED, and policy_decision is null. Packaging metadata is informational by path only. Differences are review evidence, not malware verdicts. Source-only files are reported as removed, including files a legitimate build may intentionally omit.

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

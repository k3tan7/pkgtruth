# Report contract 1.1 (legacy 1.0 readable)

The authoritative machine-readable schema is [report.schema.json](report.schema.json), generated from `pkgtruth.models.Report` by `examples/generate.py`. Unknown fields are rejected. Empty arrays/nulls reserve later features without pretending those features ran.

- `scan_id`: deterministic 32-character hex identity over artifact hash, full source-tree hash, source prefix and rule version.
- `analysis_status`: COMPLETE, PARTIAL or REJECTED. Unsafe inputs raise an explicit error and do not create a report; successful comparisons can be COMPLETE or PARTIAL.
- `input_artifact`, `artifact_sha256`, `source_tree_sha256`: supplied artifact label and inspected content identity. Source-tree hashing serializes sorted relative paths and content hashes.
- `source_resolution`: LOCAL_USER_MAPPING; `source_commit`: null. No authenticated source origin.
- `mappings`: explicit source and artifact prefixes plus mapping method.
- `file_differences`: status relative to selected source scope, hashes, classification, evidence ID, binary flag, bounded unified diff and preview-truncation flag.
- `record_status`: VALID, INVALID, UNAVAILABLE, UNRESOLVED or legacy NOT_CHECKED. `record_check` contains status, path, checked-file count and per-path reasons. VALID means internal consistency only; `provenance_status` remains NOT_CHECKED.
- `behavior_indicators`: stable indicator IDs, rule kinds, file/line/symbol, NEW/PRESENT/SOURCE_ONLY/UNKNOWN relation, conservative explanations and evidence references.
- `metadata_changes`: declared dependency/script values on both sides, baseline path, PRESENT/CHANGED/UNKNOWN relation and evidence references.
- `coverage`: file/status counts, source exclusions and per-file byte limit.
- `findings`: stable IDs, deterministic rule, severity and existing evidence references. No claims of malicious execution.
- `evidence`: stable IDs, path, description and bounded source/artifact excerpts (null for absent/non-text content).
- `model_status`: NOT_CONFIGURED; `ai_assessments`, `historical_anomalies`: empty; `policy_decision`: null.
- `limitations`, `tool_version`, `rule_version`, `schema_version`: scope, uncertainty and reproducibility metadata.

Added means present only in artifact; removed means present only in source. Identical means byte-identical, even for binaries. Known metadata paths under a top-level `.dist-info` directory are informational by convention; arbitrary code gets no blanket metadata exemption. File matching is case-sensitive despite case aliases being rejected within either input. Neither metadata classification nor matching bytes imply safety.

Schema 1.0 stored reports remain readable. Missing added fields default to NOT_CHECKED/empty; old evidence is never relabeled as newly checked. New scans use tool 0.2.0 and rule static-security-2 in their identities. See SECURITY_RULES.md for supported checks and coverage limits.

## Current schema 1.2 — consolidated integration

New scans use tool 0.3.0 and schema 1.2; the original schema 1.0 and 1.1 report serialization remains supported without fabricated new checks. The preceding 1.1 fields describe the historical contract; these current fields supersede its reserved feature statuses:

- `package_name`, `package_version`: bounded declared wheel identity, also checked against PyPI metadata on registry scans.
- `retrieval`: exact registry URL/artifact digest/size and verification result; `source_commit` and `source_resolution` describe unverified exact-tag correspondence, or explicit artifact-only uncertainty. No provenance verification is implemented.
- `model_status`: NOT_CONFIGURED, VALIDATED, UNAVAILABLE or REJECTED. `model_details` records actual runtime, digest/license metadata, prompt hash, options and available timing/token usage. `ai_assessments` contain schema-validated hypotheses with offered evidence references; VALIDATED refers to structure/references, not factual truth.
- `release_fingerprint`: artifact file hashes, bounded imports, capability surfaces, declarations and `coverage_limited`. `dna_baseline` identifies the selected comparison; `historical_anomalies` cite new/changed-file, import/declaration and first-observed capability evidence. Partial history is explicit; no trained anomaly model or full release history claim.
- `impact_relationships`: bounded conditional static relationships with evidence IDs. `impact_truncated` exposes the edge cap. These are not execution traces.
- `policy_decision`: typed ALLOW/REVIEW/BLOCK, exact policy configuration, rule/reason/finding/evidence IDs and explicit ALLOW caveat. AI cannot change these decisions. Synthetic E-P evidence describes deterministic input coverage/RECORD/provenance states; E-DNA evidence describes historical comparisons.

Scan identity describes artifact/source/rule inputs. Re-running AI, selecting a DNA baseline or evaluating another policy updates annotations on that scan, rather than inventing another artifact identity. JSON and standalone HTML capsules serialize the same current Report and are not cryptographically signed or tamper-proof. Consumers must treat report text, model output and imported reports as untrusted.

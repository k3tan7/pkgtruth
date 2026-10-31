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

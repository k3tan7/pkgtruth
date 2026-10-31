# Report contract 1.0

The authoritative machine-readable schema is [report.schema.json](report.schema.json), generated from `pkgtruth.models.Report` by `examples/generate.py`. Unknown fields are rejected. Empty arrays/nulls reserve later features without pretending those features ran.

- `scan_id`: deterministic 32-character hex identity over artifact hash, full source-tree hash, source prefix and rule version.
- `analysis_status`: COMPLETE, PARTIAL or REJECTED. Unsafe inputs raise an explicit error and do not create a report; successful comparisons can be COMPLETE or PARTIAL.
- `input_artifact`, `artifact_sha256`, `source_tree_sha256`: supplied artifact label and inspected content identity. Source-tree hashing serializes sorted relative paths and content hashes.
- `source_resolution`: LOCAL_USER_MAPPING; `source_commit`: null. No authenticated source origin.
- `mappings`: explicit source and artifact prefixes plus mapping method.
- `file_differences`: status relative to selected source scope, hashes, classification, evidence ID, binary flag, bounded unified diff and preview-truncation flag.
- `record_status`, `provenance_status`: NOT_CHECKED in this milestone.
- `coverage`: file/status counts, source exclusions and per-file byte limit.
- `findings`: stable IDs, deterministic rule, severity and existing evidence references. No claims of malicious execution.
- `evidence`: stable IDs, path, description and bounded source/artifact excerpts (null for absent/non-text content).
- `model_status`: NOT_CONFIGURED; `ai_assessments`, `historical_anomalies`: empty; `policy_decision`: null.
- `limitations`, `tool_version`, `rule_version`, `schema_version`: scope, uncertainty and reproducibility metadata.

Added means present only in artifact; removed means present only in source. Identical means byte-identical, even for binaries. Metadata under a top-level `.dist-info` directory is informational by path convention. File matching is case-sensitive despite case aliases being rejected within either input. Neither metadata classification nor matching bytes imply safety.

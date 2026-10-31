"""Versioned public report contract. No numerical trust scores."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_serializer


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Difference(StrictModel):
    path: str
    source_path: str | None
    status: Literal['added', 'removed', 'modified', 'identical']
    artifact_sha256: str | None
    source_sha256: str | None
    classification: Literal['packaging_metadata', 'packaging_configuration', 'unexplained', 'identical']
    evidence_id: str
    binary: bool = False
    diff: str = ''
    excerpt_truncated: bool = False


class Evidence(StrictModel):
    id: str
    path: str
    description: str
    source_excerpt: str | None = None
    artifact_excerpt: str | None = None


class Finding(StrictModel):
    id: str
    rule: str
    severity: Literal['HIGH', 'MEDIUM', 'INFORMATIONAL']
    explanation: str
    evidence_ids: list[str]


class Mapping(StrictModel):
    source_prefix: str
    artifact_prefix: str = ''
    method: Literal['explicit_relative_path'] = 'explicit_relative_path'


class Coverage(StrictModel):
    artifact_files: int
    source_files: int
    compared_files: int
    identical: int
    added: int
    removed: int
    modified: int
    excluded_source_files: int
    byte_limit_per_file: int


class RecordIssue(StrictModel):
    path: str | None
    reason: str


class RecordCheck(StrictModel):
    status: Literal['NOT_CHECKED', 'VALID', 'INVALID', 'UNAVAILABLE', 'UNRESOLVED'] = 'NOT_CHECKED'
    path: str | None = None
    checked_files: int = 0
    issues: list[RecordIssue] = Field(default_factory=list)


class BehaviorIndicator(StrictModel):
    id: str
    kind: str
    path: str
    line: int
    symbol: str
    relation: Literal['NEW', 'PRESENT', 'SOURCE_ONLY', 'UNKNOWN']
    explanation: str
    evidence_ids: list[str]


class MetadataChange(StrictModel):
    path: str
    field: Literal['dependencies', 'console_scripts', 'gui_scripts']
    source_path: str | None
    source_values: list[str] | None
    artifact_values: list[str]
    relation: Literal['PRESENT', 'CHANGED', 'UNKNOWN']
    evidence_ids: list[str]


class Report(StrictModel):
    schema_version: Literal['1.0', '1.1', '1.2'] = '1.2'
    tool_version: str = '0.3.0'
    rule_version: str = 'static-security-2'
    scan_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    analysis_status: Literal['COMPLETE', 'PARTIAL', 'REJECTED']
    input_artifact: str
    source_resolution: Literal['LOCAL_USER_MAPPING', 'PYPI_TAG_UNVERIFIED', 'ARTIFACT_ONLY'] = 'LOCAL_USER_MAPPING'
    artifact_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    source_tree_sha256: str
    source_commit: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    retrieval: dict = Field(default_factory=dict)
    mappings: list[Mapping]
    file_differences: list[Difference]
    record_status: Literal['NOT_CHECKED', 'VALID', 'INVALID', 'UNAVAILABLE', 'UNRESOLVED'] = 'NOT_CHECKED'
    record_check: RecordCheck = Field(default_factory=RecordCheck)
    behavior_indicators: list[BehaviorIndicator] = Field(default_factory=list)
    metadata_changes: list[MetadataChange] = Field(default_factory=list)
    provenance_status: Literal['NOT_CHECKED'] = 'NOT_CHECKED'
    coverage: Coverage
    findings: list[Finding]
    evidence: list[Evidence]
    release_fingerprint: dict = Field(default_factory=dict)
    dna_baseline: dict = Field(default_factory=dict)
    historical_anomalies: list[dict] = Field(default_factory=list)
    model_status: Literal['NOT_CONFIGURED', 'VALIDATED', 'REJECTED', 'UNAVAILABLE'] = 'NOT_CONFIGURED'
    model_details: dict = Field(default_factory=dict)
    ai_assessments: list[dict] = Field(default_factory=list)
    policy_decision: None = None
    limitations: list[str]


    @model_serializer(mode='wrap')
    def serialize_report(self, handler):
        data = handler(self)
        if self.schema_version in ('1.0', '1.1'):
            for field in ('package_name', 'package_version', 'retrieval', 'model_details', 'release_fingerprint', 'dna_baseline'):
                data.pop(field, None)
        if self.schema_version == '1.0':
            # Preserve the strict original wire format when re-exporting stored reports.
            for field in ('record_check', 'behavior_indicators', 'metadata_changes'):
                data.pop(field, None)
        return data

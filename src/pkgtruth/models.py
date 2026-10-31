"""Versioned public report contract. No numerical trust scores."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Difference(StrictModel):
    path: str
    source_path: str | None
    status: Literal['added', 'removed', 'modified', 'identical']
    artifact_sha256: str | None
    source_sha256: str | None
    classification: Literal['packaging_metadata', 'unexplained', 'identical']
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


class Report(StrictModel):
    schema_version: Literal['1.0'] = '1.0'
    tool_version: str = '0.1.0'
    rule_version: str = 'local-comparison-1'
    scan_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    analysis_status: Literal['COMPLETE', 'PARTIAL', 'REJECTED']
    input_artifact: str
    source_resolution: Literal['LOCAL_USER_MAPPING'] = 'LOCAL_USER_MAPPING'
    artifact_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    source_tree_sha256: str
    source_commit: str | None = None
    mappings: list[Mapping]
    file_differences: list[Difference]
    record_status: Literal['NOT_CHECKED'] = 'NOT_CHECKED'
    provenance_status: Literal['NOT_CHECKED'] = 'NOT_CHECKED'
    coverage: Coverage
    findings: list[Finding]
    evidence: list[Evidence]
    historical_anomalies: list[dict] = Field(default_factory=list)
    model_status: Literal['NOT_CONFIGURED'] = 'NOT_CONFIGURED'
    ai_assessments: list[dict] = Field(default_factory=list)
    policy_decision: None = None
    limitations: list[str]

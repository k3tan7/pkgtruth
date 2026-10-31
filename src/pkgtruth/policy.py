"""Deterministic adoption checks. ALLOW is scoped checks passing, never proof of safety."""
import hashlib
import json
from pydantic import Field
from .models import Evidence, PolicyDecision, PolicyReason, StrictModel


class PolicyConfig(StrictModel):
    require_complete: bool = Field(default=True, strict=True)
    review_medium: bool = Field(default=True, strict=True)
    block_high: bool = Field(default=False, strict=True)
    require_verified_provenance: bool = Field(default=False, strict=True)


def apply_policy(report, config=None):
    config = config or PolicyConfig()
    result = report.model_copy(deep=True)
    result.schema_version = '1.2'
    result.evidence = [e for e in result.evidence if not e.id.startswith('E-P-')]
    facts = {'analysis_status': result.analysis_status, 'record_status': result.record_status,
             'provenance_status': result.provenance_status, 'configured_checks': config.model_dump()}
    eid = 'E-P-' + hashlib.sha256(json.dumps([result.scan_id, facts], sort_keys=True).encode()).hexdigest()[:16]
    result.evidence.append(Evidence(id=eid, path='<policy input statuses>', description='Deterministic policy input statuses; not authenticated report signing.', artifact_excerpt=json.dumps(facts, sort_keys=True)))
    reasons, decision = [], 'ALLOW'
    def reason(rule, level, explanation, findings=None, evidence=None):
        nonlocal decision
        if {'ALLOW':0,'REVIEW':1,'BLOCK':2}[level] > {'ALLOW':0,'REVIEW':1,'BLOCK':2}[decision]:
            decision = level
        reasons.append(PolicyReason(rule=rule, explanation=explanation, finding_ids=findings or [], evidence_ids=evidence or [eid]))
    invalid = [f for f in result.findings if f.rule == 'RECORD_INVALID']
    if result.record_status == 'INVALID':
        reason('INVALID_RECORD','BLOCK','Artifact consistency failed.',[f.id for f in invalid],[e for f in invalid for e in f.evidence_ids])
    elif result.record_status != 'VALID':
        reason('UNCHECKED_RECORD','REVIEW','RECORD consistency is unavailable, unresolved or not checked.')
    if result.provenance_status == 'INVALID':
        reason('INVALID_PROVENANCE','BLOCK','Provided provenance status is INVALID; no authentication is invented by this evaluator.')
    elif config.require_verified_provenance and result.provenance_status != 'VERIFIED':
        reason('PROVENANCE_REQUIRED','REVIEW','Policy requires verified provenance; it is not available.')
    if config.require_complete and result.analysis_status != 'COMPLETE':
        reason('INCOMPLETE_COVERAGE','REVIEW','Inspection coverage is incomplete or rejected.')
    high = [f for f in result.findings if f.severity == 'HIGH' and f.rule != 'RECORD_INVALID']
    if high:
        reason('HIGH_FINDINGS','BLOCK' if config.block_high else 'REVIEW','High-priority static findings require review; they do not prove an attack.', [f.id for f in high], [e for f in high for e in f.evidence_ids])
    medium = [f for f in result.findings if f.severity == 'MEDIUM']
    if config.review_medium and medium:
        reason('MEDIUM_FINDINGS','REVIEW','Configured checks require review of unexplained differences or capabilities.', [f.id for f in medium], [e for f in medium for e in f.evidence_ids])
    historical = [a for a in result.historical_anomalies if a.get('severity') == 'HIGH' or (config.review_medium and a.get('severity') == 'MEDIUM')]
    if historical:
        reason('HISTORICAL_CHANGES', 'BLOCK' if config.block_high and any(a.get('severity') == 'HIGH' for a in historical) else 'REVIEW',
               'First-observed historical indicators/declarations require review within the reported coverage limits.', evidence=[e for a in historical for e in a.get('evidence_ids', [])])
    if not reasons:
        reason('CONFIGURED_CHECKS_PASSED','ALLOW','Configured checks passed. This is not proof that the package is harmless.')
    known = {e.id for e in result.evidence}
    if any(not set(r.evidence_ids) <= known for r in reasons):
        raise ValueError('Policy input contains unsupported evidence references')
    result.policy_decision = PolicyDecision(decision=decision, reasons=reasons, config=config.model_dump(), limitation='Evaluates supplied report facts under configured checks, not authenticity, safety, signatures or runtime behavior.')
    return result

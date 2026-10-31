"""Deterministic release fingerprints and bounded, evidence-linked comparisons."""
import hashlib
import json
from .models import Evidence
from .inputs import InputError


def fingerprint(artifact, indicators, metadata, imports, *, partial):
    return {'version': '1', 'artifact_files': {path: hashlib.sha256(value).hexdigest() for path, value in sorted(artifact.items())},
        'imports': sorted(imports),
        'surfaces': [{'kind': i.kind, 'path': i.path, 'symbol': i.symbol, 'evidence_ids': i.evidence_ids}
                     for i in indicators if i.relation != 'SOURCE_ONLY'],
        'declarations': [{'field': c.field, 'values': c.artifact_values, 'path': c.path, 'evidence_ids': c.evidence_ids} for c in metadata],
        'coverage_limited': bool(partial)}


def compare_releases(previous, current):
    if not previous.release_fingerprint or not current.release_fingerprint:
        raise InputError('Release DNA requires reports generated with fingerprint support')
    if previous.package_name and current.package_name and previous.package_name != current.package_name:
        raise InputError('Cannot compare different package identities')
    result = current.model_copy(deep=True)
    result.schema_version = '1.2'
    result.evidence = [e for e in result.evidence if not e.id.startswith('E-DNA-')]
    result.historical_anomalies = []
    result.ai_assessments = []
    result.model_status = 'NOT_CONFIGURED'
    result.model_details = {'reason': 'Historical context changed; rerun optional local AI.'}
    result.policy_decision = None
    limited = previous.release_fingerprint['coverage_limited'] or current.release_fingerprint['coverage_limited']
    result.dna_baseline = {'scan_id': previous.scan_id, 'artifact_sha256': previous.artifact_sha256,
        'package_version': previous.package_version, 'current_version': current.package_version,
        'coverage_limited': limited, 'meaning': 'First observed only against this supplied baseline, not all releases or trained ML.'}

    def emit(kind, path, before, after, severity='INFORMATIONAL', refs=None):
        if len(result.historical_anomalies) >= 3000:
            raise InputError('Historical comparison exceeds anomaly limit')
        key = hashlib.sha256(json.dumps([previous.artifact_sha256, current.artifact_sha256, kind, path, before, after], sort_keys=True).encode()).hexdigest()[:16]
        if refs is None:
            eid = 'E-DNA-' + key
            result.evidence.append(Evidence(id=eid, path=path,
                description='Release DNA comparison against previous release (not claimed source).',
                source_excerpt=json.dumps({'previous_release': before})[:2048], artifact_excerpt=json.dumps({'current_release': after})[:2048]))
            refs = [eid]
        result.historical_anomalies.append({'id': 'DNA-' + key, 'kind': kind, 'path': path, 'previous': before,
            'current': after, 'severity': severity, 'evidence_ids': refs, 'coverage_limited': limited,
            'explanation': 'Observed in inspected data relative to the selected baseline; execution and first-ever occurrence are not established.'})

    old, new = previous.release_fingerprint, current.release_fingerprint
    for path in sorted(old['artifact_files'].keys() | new['artifact_files'].keys()):
        before, after = old['artifact_files'].get(path), new['artifact_files'].get(path)
        if before != after:
            emit('FILE_ADDED' if before is None else 'FILE_REMOVED' if after is None else 'FILE_CHANGED', path, before, after)
    old_surfaces = {(s['kind'], s['path'], s['symbol']) for s in old['surfaces']}
    for surface in new['surfaces']:
        if (surface['kind'], surface['path'], surface['symbol']) not in old_surfaces:
            emit('FIRST_OBSERVED_' + surface['kind'], surface['path'], None, surface['symbol'],
                'HIGH' if surface['kind'] in ('PTH_EXECUTION', 'CUSTOMIZE_MODULE') else 'MEDIUM', surface['evidence_ids'])
    for module in sorted(set(new['imports']) - set(old['imports'])):
        emit('FIRST_OBSERVED_IMPORT', '<import inventory>', None, module)
    def declarations(value):
        output = {}
        for item in value['declarations']:
            output.setdefault(item['field'], set()).update(item['values'])
        return {key: sorted(values) for key, values in output.items()}
    before, after = declarations(old), declarations(new)
    for field in sorted(before.keys() | after.keys()):
        if before.get(field) != after.get(field):
            emit('DECLARATION_CHANGED', field, before.get(field), after.get(field), 'MEDIUM')
    if len(result.historical_anomalies) > 3000:
        raise InputError('Historical comparison exceeds anomaly limit')
    from .policy import apply_policy, PolicyConfig
    config = PolicyConfig.model_validate(current.policy_decision.config) if current.policy_decision else PolicyConfig()
    return apply_policy(result, config)

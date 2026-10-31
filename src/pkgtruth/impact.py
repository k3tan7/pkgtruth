"""Static relationships only: declares, contains, or may activate; never a runtime trace."""
import re

MAX_EDGES = 2500


def relationships(files, indicators, metadata):
    output = []
    for indicator in indicators:
        if indicator.relation == 'SOURCE_ONLY':
            continue
        if indicator.kind in ('PTH_EXECUTION', 'CUSTOMIZE_MODULE'):
            output.append({'origin':'Python site initialization (conditional)', 'target':indicator.path,
                           'relationship':'may process/import if installed and enabled', 'evidence_ids':indicator.evidence_ids})
            match = re.match(r'import[ \t]+([A-Za-z_]\w*(?:\.\w+)*)', indicator.symbol) if indicator.kind == 'PTH_EXECUTION' else None
            if match:
                module = match.group(1).replace('.', '/')
                for target in (module + '.py', module + '/__init__.py'):
                    if target in files:
                        output.append({'origin':indicator.path,'target':target,'relationship':'directive names this module; reachability unverified','evidence_ids':indicator.evidence_ids})
        else:
            output.append({'origin':indicator.path,'target':indicator.kind + ': ' + indicator.symbol,
                'relationship':'contains static indicator; execution not established','evidence_ids':indicator.evidence_ids})
    for change in metadata:
        if change.field not in ('console_scripts','gui_scripts'):
            continue
        for value in change.artifact_values:
            match = re.fullmatch(r'([^=]+)=\s*([A-Za-z_]\w*(?:\.\w+)*):[^\s]+(?:\s+\[[^\]]+\])?',value)
            if match:
                module=match.group(2).replace('.','/')
                target=next((p for p in (module+'.py',module+'/__init__.py') if p in files), match.group(2)+' (unresolved target)')
                output.append({'origin':'Entry point '+match.group(1).strip(),'target':target,
                    'relationship':'declares target; invocation not established','evidence_ids':change.evidence_ids})
    return output[:MAX_EDGES], len(output) > MAX_EDGES

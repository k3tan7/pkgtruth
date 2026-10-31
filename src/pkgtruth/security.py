"""Bounded static checks. Never import, install or execute target code."""
from __future__ import annotations

import ast
import base64
import configparser
import csv
import hashlib
import io
import json
import re
import tokenize
import tomllib
from email import policy
from email.parser import BytesParser

from .inputs import InputError, MAX_FILES, collision_key, safe_path
from .models import BehaviorIndicator, Evidence, Finding, MetadataChange, RecordCheck, RecordIssue

MAX_PARSE = 128 * 1024
MAX_NODES = 20000
MAX_INDICATORS = 2000
SOURCE_CONFIGURATION = {'pyproject.toml', 'setup.cfg', 'setup.py', 'MANIFEST.in', 'PKG-INFO'}
HASHES = {'sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512', 'blake2b', 'blake2s'}
NETWORK = {'socket', 'ssl', 'http', 'urllib', 'requests', 'httpx', 'aiohttp', 'ftplib', 'smtplib', 'websockets'}


def identity(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:16]


def validate_record(files: dict[str, bytes]) -> RecordCheck:
    roots = {name.split('/')[0] for name in files if '/' in name and name.split('/')[0].endswith('.dist-info')}
    records = [name for name in files if len(name.split('/')) == 2 and name.endswith('.dist-info/RECORD')]
    if not records:
        return RecordCheck(status='UNAVAILABLE', issues=[RecordIssue(path=None, reason='No top-level wheel RECORD is present')])
    if len(records) != 1 or len(roots) != 1:
        return RecordCheck(status='INVALID', issues=[RecordIssue(path=None, reason='Ambiguous distribution metadata or multiple RECORD files')])
    path = records[0]
    if len(files[path]) > MAX_PARSE:
        return RecordCheck(status='UNRESOLVED', path=path, issues=[RecordIssue(path=path, reason='RECORD exceeds parser byte limit')])
    issues = []
    seen = set()
    names = set()
    checked = 0
    unsupported = False
    invalid = False
    fully_read = True
    signatures = {path + '.jws', path + '.p7s'}

    def issue(name, reason, *, unresolved=False):
        nonlocal invalid, unsupported
        issues.append(RecordIssue(path=name, reason=reason))
        unsupported |= unresolved
        invalid |= not unresolved

    try:
        reader = csv.reader(io.StringIO(files[path].decode('utf-8'), newline=''), strict=True)
        for index, row in enumerate(reader):
            if index >= MAX_FILES + 3:
                issue(path, 'RECORD exceeds row limit', unresolved=True)
                fully_read = False
                break
            if len(row) != 3:
                issue(path, f'Row {index + 1} must have exactly three fields')
                continue
            name, digest, size = row
            try:
                safe_path(name)
            except InputError:
                issue(path, f'Row {index + 1} contains an unsafe path')
                continue
            key = collision_key(name)
            if key in seen:
                issue(name, 'Duplicate or normalized-colliding RECORD path')
                continue
            seen.add(key)
            names.add(name)
            if name not in files:
                issue(name, 'RECORD refers to an absent artifact file')
                continue
            if name in signatures:
                issue(name, 'Deprecated signature files must not be listed in RECORD')
                continue
            if name == path:
                if digest:
                    issue(name, 'RECORD self-entry hash must be blank')
                if size and (not re.fullmatch(r'[0-9]{1,10}', size) or int(size) != len(files[name])):
                    issue(name, 'RECORD self-entry size is malformed or mismatches content')
                continue
            if not size:
                issue(name, 'No size declared; size validation is unavailable', unresolved=True)
            elif not re.fullmatch(r'[0-9]{1,10}', size) or int(size) != len(files[name]):
                issue(name, 'Recorded size is malformed or mismatches content')
            algorithm, separator, encoded = digest.partition('=')
            if not separator or not re.fullmatch(r'[A-Za-z0-9_-]+', encoded):
                issue(name, 'Hash must use an algorithm and unpadded URL-safe base64 digest')
                continue
            if algorithm in {'md5', 'sha1', 'sha224'}:
                issue(name, 'Insecure digest algorithm is forbidden')
                continue
            if algorithm not in HASHES:
                issue(name, f'Unsupported digest algorithm: {algorithm[:80]}', unresolved=True)
                continue
            expected = base64.urlsafe_b64encode(hashlib.new(algorithm, files[name]).digest()).decode().rstrip('=')
            if encoded != expected:
                issue(name, 'Recorded hash mismatches content or digest encoding')
            checked += 1
    except (UnicodeError, csv.Error, ValueError) as exc:
        issue(path, f'RECORD is not valid UTF-8 CSV ({type(exc).__name__})')
        fully_read = False
    for missing in sorted(files.keys() - names - signatures) if fully_read else []:
        issue(missing, 'Artifact file is not listed in RECORD')
    return RecordCheck(status='INVALID' if invalid else 'UNRESOLVED' if unsupported else 'VALID',
                       path=path, checked_files=checked, issues=issues)


def logical_path(path: str) -> str:
    parts = path.split('/')
    if len(parts) > 2 and parts[0].endswith('.data') and parts[1] in ('purelib', 'platlib'):
        return '/'.join(parts[2:])
    return path


def decode_python(data: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    return data.decode(encoding)


def features(path: str, data: bytes, deadline, imports=None) -> dict[tuple[str, str], tuple[int, str]]:
    """Return syntactic indicators, keyed without line numbers to tolerate line moves."""
    result = {}
    logical = logical_path(path)
    if data.startswith((b'\x7fELF', b'MZ', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\x00asm')) or path.lower().endswith(('.so', '.pyd', '.dll', '.exe', '.dylib')):
        result[('NATIVE_BINARY', 'binary content')] = (1, 'Native/binary content may contain behavior unavailable to Python AST inspection.')
    if path.endswith('.pyc'):
        result[('BYTECODE', 'Python bytecode')] = (1, 'Bytecode is not decompiled or verified against source.')
    if logical in ('sitecustomize.py', 'usercustomize.py', 'sitecustomize/__init__.py', 'usercustomize/__init__.py'):
        result[('CUSTOMIZE_MODULE', logical.split('/')[0].removesuffix('.py'))] = (1, 'Importable customization module is a possible Python startup surface, depending on site configuration.')
    if path.endswith('.pth'):
        if len(data) > MAX_PARSE:
            raise ValueError('PTH exceeds parser byte limit')
        text = data.decode('utf-8')
        if '/' not in logical:
            for line_number, line in enumerate(text.splitlines(), 1):
                # Python site.py recognizes import + space/tab at column zero.
                if line.startswith(('import ', 'import\t')):
                    result[('PTH_EXECUTION', line.rstrip())] = (line_number, 'Executable .pth directive is a possible startup surface when installed in a processed site directory.')
    if not path.endswith('.py'):
        return result
    if len(data) > MAX_PARSE:
        raise ValueError('Python source exceeds parser byte limit')
    text = decode_python(data)
    tree = ast.parse(text)
    aliases = {}
    nodes = []
    for node in ast.walk(tree):
        if len(nodes) >= MAX_NODES:
            raise ValueError('Python AST exceeds node limit')
        if len(nodes) % 256 == 0:
            deadline()
        nodes.append(node)
        if imports is not None and len(imports) > 2000:
            retained = sorted(imports)[:2000]
            imports.clear()
            imports.update(retained)
            raise ValueError('Import inventory limit exceeded')
        if isinstance(node, ast.Import):
            if imports is not None:
                imports.update(alias.name for alias in node.names)
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            if imports is not None:
                if node.module:
                    imports.add('.' * node.level + node.module)
                else:
                    imports.update('.' * node.level + alias.name for alias in node.names)
            if node.level or not node.module:
                continue
            for alias in node.names:
                if alias.name != '*':
                    aliases[alias.asname or alias.name] = node.module + '.' + alias.name
    for node in nodes:
        if len(result) > MAX_INDICATORS:
            raise ValueError('Indicator limit exceeded')
        references = []
        if isinstance(node, ast.Import):
            references = [(alias.name, 'import') for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            references = [(node.module, 'import')]
        elif isinstance(node, ast.Call):
            function = node.func
            parts = []
            while isinstance(function, ast.Attribute):
                parts.insert(0, function.attr)
                function = function.value
            if isinstance(function, ast.Name):
                references = [('.'.join([aliases.get(function.id, function.id), *parts]), 'call')]
        for symbol, mode in references:
            root = symbol.split('.')[0]
            kind = None
            if root in NETWORK:
                kind = 'NETWORK_CAPABILITY'
            elif root == 'subprocess' or symbol in ('os.system', 'os.popen', 'os.spawnl', 'os.spawnv', 'os.execv', 'os.execve'):
                kind = 'SUBPROCESS_CAPABILITY'
            elif mode == 'call' and symbol in ('exec', 'eval', 'compile'):
                kind = 'DYNAMIC_EXECUTION'
            elif mode == 'call' and symbol in ('__import__', 'importlib.import_module'):
                kind = 'DYNAMIC_IMPORT'
            if kind:
                result[(kind, mode + ': ' + symbol)] = (node.lineno, 'Syntactic module reference or call; bindings, control flow, reachability and actual execution are not established.')
    return result


def packaging_metadata(path: str) -> bool:
    parts = path.split('/')
    return len(parts) >= 2 and parts[0].endswith('.dist-info') and (
        (len(parts) == 2 and parts[1] in {'METADATA', 'WHEEL', 'RECORD', 'RECORD.jws', 'RECORD.p7s', 'entry_points.txt', 'top_level.txt'})
        or (len(parts) > 2 and parts[1] in {'licenses', 'license_files', 'LICENSES', 'sboms'} and not path.endswith(('.py', '.pth', '.pyc'))))


def declarations(files: dict[str, bytes], deadline):
    """Only read metadata explicitly inside the mapped source scope; never setup.py."""
    values = {}
    total_bytes = 0
    for path, data in sorted(files.items()):
        deadline()
        relevant = path in ('pyproject.toml', 'PKG-INFO') or (len(path.split('/')) == 2 and path.endswith(('.dist-info/METADATA', '.dist-info/entry_points.txt')))
        if relevant:
            total_bytes += len(data)
            if total_bytes > MAX_PARSE:
                raise ValueError('Cumulative metadata parser byte limit exceeded')
        if path == 'pyproject.toml':
            if len(data) > MAX_PARSE:
                raise ValueError('pyproject.toml exceeds parser limit')
            project = tomllib.loads(data.decode('utf-8')).get('project')
            if project is None:
                continue
            if not isinstance(project, dict):
                raise ValueError('Invalid project metadata')
            dynamic = project.get('dynamic', [])
            if not isinstance(dynamic, list) or any(not isinstance(v, str) for v in dynamic):
                raise ValueError('Invalid dynamic project declarations')
            deps = project.get('dependencies', [])
            if not isinstance(deps, list) or any(not isinstance(v, str) for v in deps):
                raise ValueError('Invalid project dependencies')
            if 'dependencies' not in dynamic:
                values[(path, 'dependencies')] = sorted(set(v.strip() for v in deps))
            for key, group in [('scripts', 'console_scripts'), ('gui-scripts', 'gui_scripts')]:
                entries = project.get(key, {})
                if not isinstance(entries, dict) or any(not isinstance(v, str) for v in entries.values()):
                    raise ValueError('Invalid project entry points')
                if key not in dynamic:
                    values[(path, group)] = sorted(f'{k} = {v.strip()}' for k, v in entries.items())
        elif path == 'PKG-INFO' or (len(path.split('/')) == 2 and path.endswith('.dist-info/METADATA')):
            if len(data) > MAX_PARSE:
                raise ValueError('METADATA exceeds parser limit')
            message = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
            if message.defects or any(len(message.get_all(key, [])) != 1 for key in ('Name', 'Version')):
                raise ValueError('Malformed metadata headers')
            values[(path, 'dependencies')] = sorted(set(str(v).strip() for v in message.get_all('Requires-Dist', [])))
            if path.endswith('.dist-info/METADATA') and path.removesuffix('METADATA') + 'entry_points.txt' not in files:
                for group in ('console_scripts', 'gui_scripts'):
                    values[(path, group)] = []
        elif len(path.split('/')) == 2 and path.endswith('.dist-info/entry_points.txt'):
            if len(data) > MAX_PARSE:
                raise ValueError('Entry points exceed parser limit')
            parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=('=',))
            parser.optionxform = str
            parser.read_string(data.decode('utf-8'))
            if parser.defaults():
                raise ValueError('Entry point DEFAULT sections are unsupported')
            for group in ('console_scripts', 'gui_scripts'):
                values[(path, group)] = sorted(f'{k} = {v.strip()}' for k, v in parser.items(group)) if parser.has_section(group) else []
    if sum(len(items) for items in values.values()) > 256:
        raise ValueError('Metadata declaration count limit exceeded')
    return values


def inspect_security(artifact, source, differences, evidence, findings, deadline, *, source_available=True):
    record = validate_record(artifact)
    record_id = 'E-R-' + identity([record.model_dump(), [(p, hashlib.sha256(v).hexdigest()) for p, v in sorted(artifact.items())]])
    evidence.append(Evidence(id=record_id, path=record.path or '<wheel inventory>',
        description=f'RECORD consistency {record.status}: {record.checked_files} file digests checked. This is not provenance verification.',
        artifact_excerpt='\n'.join(f'{i.path or "<wheel>"}: {i.reason}' for i in record.issues)[:2048]))
    if record.status != 'VALID':
        findings.append(Finding(id='F-R-' + record_id[4:], rule='RECORD_' + record.status,
            severity='HIGH' if record.status == 'INVALID' else 'MEDIUM', evidence_ids=[record_id],
            explanation=f'Wheel RECORD is {record.status}. Inspect the consistency issues; no publisher authenticity is established.'))
    indicators, changes, notes = [], [], []
    imports = {'artifact': set(), 'source': set()}
    partial = record.status != 'VALID'
    for path in sorted(artifact.keys() | source.keys()):
        deadline()
        if len(indicators) >= MAX_INDICATORS:
            notes.append('Global indicator limit reached; remaining static inspection was skipped.')
            partial = True
            break
        sides = []
        for label, files in [('artifact', artifact), ('source', source)]:
            try:
                sides.append(features(path, files[path], deadline, imports[label]) if path in files else {})
            except InputError:
                raise
            except (SyntaxError, UnicodeError, ValueError, RecursionError, MemoryError) as exc:
                sides.append(None)
                notes.append(f'{label} {path}: static parser unavailable ({type(exc).__name__}: {str(exc)[:160]}); capabilities may be missed.')
                partial = True
        published, reviewed = sides
        for kind, symbol in sorted((published or {}).keys() | (reviewed or {}).keys()):
            deadline()
            if len(indicators) >= MAX_INDICATORS:
                notes.append('Global indicator limit reached; remaining indicators were skipped.')
                partial = True
                break
            current = (published or {}).get((kind, symbol))
            previous = (reviewed or {}).get((kind, symbol))
            relation = 'UNKNOWN' if not source_available or published is None or reviewed is None else 'PRESENT' if current and previous else 'NEW' if current else 'SOURCE_ONLY'
            line, explanation = current or previous
            key = identity([kind, path, symbol, relation, hashlib.sha256(artifact.get(path, b'')).hexdigest(), hashlib.sha256(source.get(path, b'')).hexdigest()])
            eid = 'E-S-' + key
            def excerpt(data, position):
                return '\n'.join(data.decode('utf-8', errors='replace').splitlines()[max(0, position - 2):position + 1])[:2048]
            evidence.append(Evidence(id=eid, path=path, description=f'{kind} at line {line}: {symbol[:256]} ({relation} relative to mapped source)',
                artifact_excerpt=excerpt(artifact[path], current[0]) if current else None,
                source_excerpt=excerpt(source[path], previous[0]) if previous else None))
            indicators.append(BehaviorIndicator(id='I-' + key, kind=kind, path=path, line=line,
                symbol=symbol[:512], relation=relation, explanation=explanation, evidence_ids=[eid]))
            if current:
                startup = kind in ('PTH_EXECUTION', 'CUSTOMIZE_MODULE')
                severity = 'HIGH' if startup and relation == 'NEW' else 'INFORMATIONAL' if relation == 'PRESENT' else 'MEDIUM'
                findings.append(Finding(id='F-S-' + key, rule=kind, severity=severity, evidence_ids=[eid],
                    explanation=f'{path}:{line}: {kind}, {relation} relative to mapped source. {explanation}'))
    declarations_by_side = []
    for label, files in [('artifact', artifact), ('source', source)]:
        try:
            declarations_by_side.append(declarations(files, deadline))
        except InputError:
            raise
        except (ValueError, UnicodeError, configparser.Error, RecursionError, MemoryError) as exc:
            declarations_by_side.append({})
            notes.append(f'{label} metadata parser unavailable ({type(exc).__name__}: {str(exc)[:160]}); declaration comparison is incomplete.')
            partial = True
    published, reviewed = declarations_by_side
    file_evidence = {d.path: d.evidence_id for d in differences}
    if len(published) > 128:
        notes.append('Metadata comparison count limit reached; remaining declarations were skipped.')
        partial = True
    for (path, field), current in sorted(published.items())[:128]:
        # Exact-path baseline wins; otherwise accept a single in-scope declaration.
        candidates = [(p, v) for (p, f), v in reviewed.items() if f == field]
        baseline = (path, reviewed[(path, field)]) if (path, field) in reviewed else candidates[0] if len(candidates) == 1 else None
        before = baseline[1] if baseline else None
        relation = 'UNKNOWN' if before is None else 'PRESENT' if before == current else 'CHANGED'
        refs = [file_evidence[path]]
        if baseline and baseline[0] != path:
            refs.append(file_evidence[baseline[0]])
        changes.append(MetadataChange(path=path, field=field, source_path=baseline[0] if baseline else None,
            source_values=before, artifact_values=current, relation=relation, evidence_ids=refs))
        if relation == 'CHANGED' or (field != 'dependencies' and current and relation == 'UNKNOWN'):
            findings.append(Finding(id='F-M-' + identity([path, field, before, current]), rule='DEPENDENCY_CHANGE' if field == 'dependencies' else 'ENTRY_POINT_CHANGE',
                severity='MEDIUM', evidence_ids=refs, explanation=f'{field} declarations in {path}: {relation}. Declarative metadata is not proof of installation or execution.'))
    if published and not reviewed:
        notes.append('No in-scope source metadata baseline: dependency/entry-point changes cannot be established. Choose a source root containing static project metadata to compare declarations.')
    return record, indicators, changes, partial, notes, imports['artifact']


def wheel_identity(files):
    paths=[p for p in files if len(p.split('/'))==2 and p.endswith('.dist-info/METADATA')]
    if len(paths)!=1 or len(files[paths[0]])>MAX_PARSE:
        return None,None
    try:
        metadata=BytesParser(policy=policy.default).parsebytes(files[paths[0]],headersonly=True)
        if metadata.defects or any(len(metadata.get_all(k,[]))!=1 for k in ('Name','Version')):
            return None,None
        name,version=str(metadata['Name']).strip(),str(metadata['Version']).strip()
        return (name,version) if name and version and max(len(name),len(version))<=100 else (None,None)
    except (ValueError,UnicodeError):
        return None,None

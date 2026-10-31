"""Generate inert, deterministic fixtures and real reports. Requires installed pkgtruth."""
import io
import json
import zipfile
from pathlib import Path

from pkgtruth.analysis import analyze
from pkgtruth.models import Report

ROOT = Path(__file__).resolve().parent


def archive(files):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_STORED) as bundle:
        for path, content in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, content)
    return result.getvalue()


def main():
    source = {
        'demo/__init__.py': b'"""Inert pkgtruth example."""\nVALUE = 1\n',
        'demo/message.py': b'def message():\n    return "reviewed source"\n',
    }
    for name, content in source.items():
        target = ROOT / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (ROOT / 'source.zip').write_bytes(archive(source))
    metadata = {
        'demo-1.0.dist-info/METADATA': b'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n',
        'demo-1.0.dist-info/WHEEL': b'Wheel-Version: 1.0\nGenerator: pkgtruth-example\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    for label in ('clean', 'tampered', 'startup', 'record-mismatch'):
        payload = {**source, **metadata}
        if label in ('tampered', 'startup', 'record-mismatch'):
            payload['demo/message.py'] = b'def message():\n    return "changed after review"\n'
            payload['demo/extra.py'] = b'UNEXPECTED = True\n'
        if label == 'startup':
            payload['startup.pth'] = b'import demo; demo.VALUE = 2\n'
            payload['demo/message.py'] = b'import socket\n\ndef message():\n    return "changed after review"\n'
            payload['demo-1.0.dist-info/entry_points.txt'] = b'[console_scripts]\ndemo=demo.message:message\n'
        # Generate a self-consistent RECORD first; the mismatch case mutates afterward.
        import base64
        import csv
        import hashlib
        rows = []
        for name, content in sorted(payload.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip('=')
            rows.append([name, 'sha256=' + digest, str(len(content))])
        rows.append(['demo-1.0.dist-info/RECORD', '', ''])
        text = io.StringIO(newline='')
        csv.writer(text, lineterminator='\n').writerows(rows)
        payload['demo-1.0.dist-info/RECORD'] = text.getvalue().encode()
        if label == 'record-mismatch':
            payload['demo/message.py'] = b'def message():\n    return "changed after RECORD was written"\n'
        wheel = archive(payload)
        (ROOT / f'{label}.whl').write_bytes(wheel)
        report = analyze(wheel, archive(source), artifact_name=f'{label}.whl')
        (ROOT / f'{label}.report.json').write_text(report.model_dump_json(indent=2) + '\n')
    (ROOT.parent / 'docs' / 'report.schema.json').write_text(json.dumps(Report.model_json_schema(), indent=2) + '\n')


if __name__ == '__main__':
    main()

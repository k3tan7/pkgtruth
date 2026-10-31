import io
import base64
import csv
import hashlib
import zipfile
import pytest


def make_zip(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, value in files.items():
            archive.writestr(path, value)
    return buffer.getvalue()


def wheel_files(files):
    payload = {
        'demo-1.0.dist-info/METADATA': b'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n',
        'demo-1.0.dist-info/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        **files,
    }
    record = 'demo-1.0.dist-info/RECORD'
    text = io.StringIO(newline='')
    writer = csv.writer(text, lineterminator='\n')
    for path, data in sorted(payload.items()):
        if path != record:
            writer.writerow([path, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='), str(len(data))])
    writer.writerow([record, '', ''])
    payload[record] = text.getvalue().encode()
    return payload


def make_wheel(files):
    return make_zip(wheel_files(files))


@pytest.fixture
def package_pair():
    source = {'demo/__init__.py': b'VALUE = 1\n', 'demo/util.py': b'def hello():\n    return "hello"\n'}
    return source, make_zip(source)


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv('PKGTRUTH_DATA_DIR', str(tmp_path / 'reports'))

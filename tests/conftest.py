import io
import zipfile
import pytest


def make_zip(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, value in files.items():
            archive.writestr(path, value)
    return buffer.getvalue()


@pytest.fixture
def package_pair():
    source = {'demo/__init__.py': b'VALUE = 1\n', 'demo/util.py': b'def hello():\n    return "hello"\n'}
    return source, make_zip(source)


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv('PKGTRUTH_DATA_DIR', str(tmp_path / 'reports'))

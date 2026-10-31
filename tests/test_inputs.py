import io
import os
import stat
import zipfile
import pytest
from pkgtruth.inputs import InputError, MAX_ARCHIVE, MAX_FILE, read_directory, read_zip
from conftest import make_zip


@pytest.mark.parametrize('name', ['../escape.py', '/absolute', 'a/../../x', 'a\\x', 'C:/x', 'a//b', './x', 'a/./b', 'a/../b', 'a\x01b'])
def test_unsafe_paths(name):
    with pytest.raises(InputError):
        read_zip(make_zip({name: b'x'}))


@pytest.mark.parametrize('names', [('A.py', 'a.py'), ('caf\u00e9.py', 'cafe\u0301.py'), ('a', 'a/b'), ('A/x', 'a/y')])
def test_collision(names):
    with pytest.raises(InputError):
        read_zip(make_zip({names[0]: b'a', names[1]: b'b'}))


def test_duplicate_members():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('a', 'x')
        with pytest.warns(UserWarning):
            archive.writestr('a', 'y')
    with pytest.raises(InputError, match='Duplicate'):
        read_zip(buffer.getvalue())


@pytest.mark.parametrize('kind', [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR])
def test_archive_links_and_special_files(kind):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        entry = zipfile.ZipInfo('x')
        entry.create_system = 3
        entry.external_attr = (kind | 0o777) << 16
        archive.writestr(entry, 'target')
    with pytest.raises(InputError, match='special'):
        read_zip(buffer.getvalue())


def test_source_links_and_hardlinks_rejected(tmp_path):
    target = tmp_path / 'outside'
    target.write_text('secret')
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'link').symlink_to(target)
    with pytest.raises(InputError):
        read_directory(source)
    (source / 'link').unlink()
    os.link(target, source / 'hardlink')
    with pytest.raises(InputError):
        read_directory(source)


def test_source_directory_symlink_rejected(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'a').write_text('a')
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'linked').symlink_to(target, target_is_directory=True)
    with pytest.raises(InputError):
        read_directory(source)


@pytest.mark.parametrize('data', [b'not zip', b'PK\x03\x04', make_zip({})])
def test_invalid_or_empty_archive(data):
    with pytest.raises(InputError):
        read_zip(data)


def test_resource_limits(monkeypatch):
    with pytest.raises(InputError, match='compressed-byte'):
        read_zip(b'x' * (MAX_ARCHIVE + 1))
    with pytest.raises(InputError):
        read_zip(make_zip({'large': b'a' * (MAX_FILE + 1)}))
    with pytest.raises(InputError, match='ratio'):
        read_zip(make_zip({'bomb': b'0' * 500000}))
    monkeypatch.setattr('pkgtruth.inputs.MAX_FILES', 2)
    with pytest.raises(InputError, match='count'):
        read_zip(make_zip({'1': b'a', '2': b'a', '3': b'a'}))


def test_expanded_total_limit(monkeypatch):
    monkeypatch.setattr('pkgtruth.inputs.MAX_TOTAL', 3)
    with pytest.raises(InputError, match='expanded-byte'):
        read_zip(make_zip({'a': b'12', 'b': b'34'}))


def test_elapsed_time_limit(monkeypatch):
    ticks = iter([0, 11])
    monkeypatch.setattr('pkgtruth.inputs.time.monotonic', lambda: next(ticks))
    with pytest.raises(InputError, match='time limit'):
        read_zip(make_zip({'a': b'x'}))


def test_target_code_never_executes(tmp_path):
    sentinel = tmp_path / 'executed'
    payload = f'open({str(sentinel)!r}, "w").write("executed")'
    files = {'setup.py': payload.encode(), 'pkg/__init__.py': payload.encode(), 'startup.pth': payload.encode()}
    read_zip(make_zip(files))
    from pkgtruth.analysis import analyze
    analyze(make_zip(files), make_zip(files))
    assert not sentinel.exists()


def test_fifo_input_is_rejected_without_blocking(tmp_path):
    from pkgtruth.inputs import read_bounded_file
    fifo = tmp_path / 'input.whl'
    os.mkfifo(fifo)
    with pytest.raises(InputError, match='regular file'):
        read_bounded_file(fifo)


def test_crc_corruption_is_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr('a.txt', b'UNIQUE-CONTENT')
    corrupted = buffer.getvalue().replace(b'UNIQUE-CONTENT', b'UNIQUE-CONTENX')
    with pytest.raises(InputError, match='Malformed'):
        read_zip(corrupted)


def test_nul_path_is_rejected():
    data = make_zip({'abc.txt': b'x'})
    data = data.replace(b'abc.txt', b'a\x00c.txt')
    with pytest.raises(InputError, match='NUL'):
        read_zip(data)

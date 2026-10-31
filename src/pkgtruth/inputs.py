"""Bounded, virtual ZIP and local-directory readers. Target code is never run."""
from __future__ import annotations

import io
import os
import stat
import time
import unicodedata
import zipfile
import zlib
from pathlib import Path

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_TOTAL = 20 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 1000
MAX_SECONDS = 10


class InputError(ValueError):
    """An input was rejected, rather than partially or silently inspected."""


def safe_path(name: str) -> str:
    if not name or len(name) > 512 or name.startswith('/') or '\\' in name:
        raise InputError('Unsafe or oversized path')
    parts = name.split('/')
    if any(p in ('', '.', '..') or ':' in p or any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        raise InputError('Unsafe path component')
    return name


def collision_key(name: str) -> str:
    return unicodedata.normalize('NFC', name).casefold()


class Budget:
    def __init__(self):
        self.started = time.monotonic()
        self.total = 0
        self.count = 0
        self.seen: set[str] = set()
        self.spellings: dict[str, str] = {}
        self.files: set[str] = set()
        self.dirs: set[str] = set()

    def add(self, name: str, size: int, directory: bool = False):
        self.check_time()
        safe_path(name)
        key = collision_key(name)
        components = name.split('/')
        for i in range(1, len(components) + 1):
            partial = '/'.join(components[:i])
            normalized = collision_key(partial)
            if normalized in self.spellings and self.spellings[normalized] != partial:
                raise InputError('Unicode or case-colliding parent path')
            self.spellings[normalized] = partial
        if key in self.seen:
            raise InputError('Duplicate, Unicode or case-colliding path')
        parents = [collision_key('/'.join(name.split('/')[:i])) for i in range(1, len(name.split('/'))) ]
        if any(parent in self.files for parent in parents) or (not directory and key in self.dirs):
            raise InputError('File/directory path collision')
        self.seen.add(key)
        self.dirs.update(parents)
        (self.dirs if directory else self.files).add(key)
        self.count += 1
        self.total += size
        if size > MAX_FILE or size < 0 or self.total > MAX_TOTAL or self.count > MAX_FILES:
            raise InputError('Input exceeds file, count or expanded-byte limit')

    def check_time(self):
        if time.monotonic() - self.started > MAX_SECONDS:
            raise InputError('Input inspection time limit exceeded')


def read_bounded_file(path: Path, limit: int = MAX_ARCHIVE) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise InputError('Input must be a regular file, not a link or special file')
        if info.st_size > limit:
            raise InputError('Input exceeds byte limit')
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise InputError('Input exceeds byte limit')
    return data


def read_zip(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE:
        raise InputError('Archive exceeds compressed-byte limit')
    budget = Budget()
    result = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > MAX_FILES:
                raise InputError('Archive exceeds entry-count limit')
            for entry in archive.infolist():
                # ZipInfo.filename truncates NUL: inspect the original name too.
                if entry.orig_filename != entry.filename:
                    raise InputError('NUL in ZIP path')
                mode = entry.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise InputError('Links and special archive entries are forbidden')
                directory = entry.is_dir()
                if (kind == stat.S_IFDIR and not directory) or (kind == stat.S_IFREG and directory):
                    raise InputError('Inconsistent ZIP entry type')
                name = entry.filename[:-1] if directory else entry.filename
                budget.add(name, entry.file_size, directory)
                if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise InputError('Encrypted or unsupported ZIP compression')
                if entry.file_size > max(entry.compress_size, 1) * 200:
                    raise InputError('Archive compression ratio exceeds limit')
                if directory:
                    if entry.file_size:
                        raise InputError('Directory entry contains data')
                    continue
                with archive.open(entry) as member:
                    content = member.read(MAX_FILE + 1)
                if len(content) != entry.file_size or len(content) > MAX_FILE:
                    raise InputError('ZIP member size mismatch or limit exceeded')
                budget.check_time()
                result[name] = content
    except InputError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, EOFError, NotImplementedError, OSError, zlib.error, ValueError) as exc:
        raise InputError('Malformed or unsupported ZIP archive') from exc
    if not result:
        raise InputError('Input contains no regular files')
    return result


def read_directory(root: Path) -> dict[str, bytes]:
    """Walk using directory descriptors; never follow links, including during reads."""
    budget = Budget()
    result = {}
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def walk_error(exc):
            raise InputError('Source directory could not be fully inspected') from exc

        for current, dirs, files, directory_fd in os.fwalk('.', follow_symlinks=False, dir_fd=root_fd, onerror=walk_error):
            prefix = '' if current == '.' else current[2:] + '/'
            for name in sorted(dirs):
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    raise InputError('Source directory links are forbidden')
                budget.add(prefix + name, 0, True)
            for name in sorted(files):
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise InputError('Source links and special files are forbidden')
                budget.add(prefix + name, info.st_size)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, 'rb') as handle:
                    opened = os.fstat(handle.fileno())
                    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                        raise InputError('Source changed during inspection')
                    content = handle.read(MAX_FILE + 1)
                if len(content) != info.st_size or len(content) > MAX_FILE:
                    raise InputError('Source changed or exceeded byte limit')
                result[prefix + name] = content
                budget.check_time()
    finally:
        os.close(root_fd)
    if not result:
        raise InputError('Source contains no regular files')
    return result

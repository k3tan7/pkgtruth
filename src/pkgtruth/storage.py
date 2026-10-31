"""Local single-user report persistence. Raw uploads are never retained."""
import os
from contextlib import contextmanager
import sqlite3
from pathlib import Path

from .models import Report


def data_directory() -> Path:
    return Path(os.environ.get('PKGTRUTH_DATA_DIR', '.pkgtruth'))


class ReportStore:
    def __init__(self, directory: Path | None = None):
        self.directory = directory if directory is not None else data_directory()

    @contextmanager
    def connect(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self.directory / 'reports.sqlite3', timeout=5)
        try:
            with connection:
                connection.execute('CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, body TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP)')
                yield connection
        finally:
            connection.close()

    def save(self, report: Report):
        with self.connect() as connection:
            connection.execute('INSERT INTO reports(id,body) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body',
                               (report.scan_id, report.model_dump_json()))

    def get(self, scan_id: str) -> Report | None:
        with self.connect() as connection:
            row = connection.execute('SELECT body FROM reports WHERE id=?', (scan_id,)).fetchone()
        return Report.model_validate_json(row[0]) if row else None

    def recent(self) -> list[Report]:
        with self.connect() as connection:
            rows = connection.execute('SELECT body FROM reports ORDER BY created DESC, id LIMIT 50').fetchall()
        return [Report.model_validate_json(row[0]) for row in rows]

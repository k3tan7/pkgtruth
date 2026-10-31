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

    def get_policy(self):
        from .policy import PolicyConfig
        with self.connect() as connection:
            connection.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            row=connection.execute("SELECT value FROM settings WHERE key='policy'").fetchone()
        return PolicyConfig.model_validate_json(row[0]) if row else PolicyConfig()

    def save_policy(self, config):
        with self.connect() as connection:
            connection.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            connection.execute("INSERT INTO settings(key,value) VALUES ('policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(config.model_dump_json(),))

    def watch_tables(self, connection):
        connection.execute('CREATE TABLE IF NOT EXISTS watchlist (name TEXT PRIMARY KEY, snapshot TEXT, generation INTEGER NOT NULL DEFAULT 0)')
        connection.execute('CREATE TABLE IF NOT EXISTS watch_events (id INTEGER PRIMARY KEY, name TEXT NOT NULL, generation INTEGER NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(name,generation))')

    def watchlist(self):
        with self.connect() as connection:
            self.watch_tables(connection)
            rows=connection.execute('SELECT name,snapshot,generation FROM watchlist ORDER BY name').fetchall()
        import json
        return [{'name':r[0],'snapshot':json.loads(r[1]) if r[1] else None,'generation':r[2]} for r in rows]

    def add_watch(self, name):
        from .pypi import package_name
        from .inputs import InputError
        name=package_name(name)
        with self.connect() as connection:
            self.watch_tables(connection)
            connection.execute('BEGIN IMMEDIATE')
            if connection.execute('SELECT count(*) FROM watchlist').fetchone()[0]>=20 and not connection.execute('SELECT 1 FROM watchlist WHERE name=?',(name,)).fetchone():
                raise InputError('Local watchlist limit is 20 packages')
            connection.execute('INSERT OR IGNORE INTO watchlist(name,generation) VALUES (?,COALESCE((SELECT MAX(generation) FROM watch_events WHERE name=?),0))',(name,name))

    def remove_watch(self, name):
        from .pypi import package_name
        with self.connect() as connection:
            self.watch_tables(connection)
            connection.execute('DELETE FROM watchlist WHERE name=?',(package_name(name),))

    def observe(self, name, current):
        import json
        from packaging.version import Version
        from .inputs import InputError
        body=json.dumps(current,sort_keys=True)
        with self.connect() as connection:
            self.watch_tables(connection)
            connection.execute('BEGIN IMMEDIATE')
            row=connection.execute('SELECT snapshot,generation FROM watchlist WHERE name=?',(name,)).fetchone()
            if row is None: raise InputError('Package is not on this watchlist')
            if row[0]==body: return {'status':'UNCHANGED','generation':row[1]}
            previous=json.loads(row[0]) if row[0] else None
            kind=('BASELINE_RECORDED' if previous is None else 'NEW_RELEASE' if Version(current['version'])>Version(previous['version']) else
                  'LATEST_VERSION_CHANGED' if current['version']!=previous['version'] else 'ARTIFACT_METADATA_CHANGED')
            generation=row[1]+1
            connection.execute('UPDATE watchlist SET snapshot=?,generation=? WHERE name=?',(body,generation,name))
            connection.execute('INSERT INTO watch_events(name,generation,kind,body) VALUES (?,?,?,?)',(name,generation,kind,body))
            connection.execute('DELETE FROM watch_events WHERE id NOT IN (SELECT id FROM watch_events ORDER BY id DESC LIMIT 200)')
        return {'status':kind,'generation':generation,'version':current['version'],'artifacts':current['artifacts']}

    def watch_events(self):
        import json
        with self.connect() as connection:
            self.watch_tables(connection)
            rows=connection.execute('SELECT name,kind,body,created FROM watch_events ORDER BY id DESC LIMIT 50').fetchall()
        return [{'name':r[0],'kind':r[1],'snapshot':json.loads(r[2]),'created_utc':r[3]} for r in rows]

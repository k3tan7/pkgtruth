"""Bounded single-process workers with persistent status and explicit restart interruption."""
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from .inputs import InputError


class JobRunner:
    def __init__(self,store):
        self.store=store
        self.gate=threading.Lock()
        self.executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='pkgtruth-local')
        with store.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, scan_id TEXT, error TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP)')
            db.execute("UPDATE jobs SET status='INTERRUPTED',error='Service restarted; submit a new job.' WHERE status IN ('QUEUED','RUNNING')")

    def run_sync(self,fn,*args,**kwargs):
        with self.gate:
            return fn(*args,**kwargs)

    def get(self,job_id):
        with self.store.connect() as db:
            row=db.execute('SELECT id,kind,status,scan_id,error,created FROM jobs WHERE id=?',(job_id,)).fetchone()
        return dict(zip(('id','kind','status','scan_id','error','created_utc'),row)) if row else None

    def submit(self,kind,payload):
        if kind not in ('pypi','ai'):
            raise InputError('Unsupported local job kind')
        job_id=uuid.uuid4().hex
        payload={**payload,'policy':self.store.get_policy().model_dump()}
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT count(*) FROM jobs WHERE status IN ('QUEUED','RUNNING')").fetchone()[0]>=2:
                raise InputError('Local job queue is full')
            db.execute('INSERT INTO jobs(id,kind,payload,status) VALUES (?,?,?,?)',(job_id,kind,json.dumps(payload),'QUEUED'))
        self.executor.submit(self.work,job_id,kind,payload)
        return job_id

    def update(self,job_id,status,scan_id=None,error=None):
        with self.store.connect() as db:
            db.execute('UPDATE jobs SET status=?,scan_id=?,error=? WHERE id=?',(status,scan_id,error,job_id))

    def work(self,job_id,kind,payload):
        with self.gate:
            self.update(job_id,'RUNNING')
            try:
                if kind=='pypi':
                    from .pypi import scan_pypi
                    from .policy import apply_policy,PolicyConfig
                    report=apply_policy(scan_pypi(payload['name'],payload['version']),PolicyConfig.model_validate(payload['policy']))
                else:
                    from .investigator import investigate
                    original=self.store.get(payload['scan_id'])
                    if original is None: raise InputError('Report not found')
                    report=investigate(original)
                self.store.save(report)
                self.update(job_id,'COMPLETE',scan_id=report.scan_id)
            except Exception as exc:
                self.update(job_id,'FAILED',error=f'{type(exc).__name__}: {str(exc)[:250]}')

    def close(self):
        self.executor.shutdown(wait=False,cancel_futures=True)

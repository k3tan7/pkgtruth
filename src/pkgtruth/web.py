"""Loopback-only local web interface; calls the same service as the CLI."""
from __future__ import annotations

import asyncio
import hmac
import re
import secrets
import sqlite3
import time
import threading
from contextlib import asynccontextmanager
from collections import deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.datastructures import UploadFile

from .analysis import analyze
from .inputs import InputError, MAX_ARCHIVE
from .storage import ReportStore

ROOT = Path(__file__).parent
MAX_REQUEST = MAX_ARCHIVE * 2 + 65536


class LocalBoundary:
    """Limit bytes before multipart parsing and reject non-loopback clients."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        client = scope.get('client')
        if client and client[0] not in ('127.0.0.1', '::1', 'testclient'):
            return await JSONResponse({'detail': 'Local single-user access only'}, status_code=403)(scope, receive, send)
        headers = dict(scope.get('headers', []))
        if scope['method'] == 'POST':
            origin=headers.get(b'origin')
            expected=(scope.get('scheme','http')+'://'+headers.get(b'host',b'').decode('latin1')).encode('latin1')
            if (origin and origin != expected) or headers.get(b'sec-fetch-site') == b'cross-site':
                return await JSONResponse({'detail':'Cross-origin request forbidden'},status_code=403)(scope,receive,send)
            try:
                length = int(headers.get(b'content-length', b'0'))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_REQUEST:
                return await JSONResponse({'detail': 'Request too large or invalid Content-Length'}, status_code=413)(scope, receive, send)
            # Buffer bounded chunks before multipart parser can spool uploads.
            chunks, total = [], 0
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                chunk = message.get('body', b'')
                total += len(chunk)
                if total > MAX_REQUEST:
                    return await JSONResponse({'detail': 'Request exceeds upload limit'}, status_code=413)(scope, receive, send)
                chunks.append(chunk)
                if not message.get('more_body', False):
                    break
            body = b''.join(chunks)
            delivered = False

            async def bounded_receive():
                nonlocal delivered
                if delivered:
                    return await receive()
                delivered = True
                return {'type': 'http.request', 'body': body, 'more_body': False}

            await self.app(scope, bounded_receive, send)
        else:
            await self.app(scope, receive, send)


def create_app(store: ReportStore | None = None) -> FastAPI:
    reports = store or ReportStore()
    from .jobs import JobRunner
    runner = JobRunner(reports)
    @asynccontextmanager
    async def lifespan(app):
        yield
        runner.close()
    app = FastAPI(title='pkgtruth', version='0.3.0', docs_url=None, redoc_url=None, lifespan=lifespan)
    lookup_times = deque()
    lookup_guard = threading.Lock()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', '[::1]', 'testserver'])
    app.add_middleware(LocalBoundary)
    app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')
    templates = Jinja2Templates(directory=ROOT / 'templates')
    scan_lock = asyncio.Lock()

    @app.middleware('http')
    async def headers(request: Request, call_next):
        response = await call_next(request)
        security_headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
        }
        for key, value in security_headers.items():
            response.headers.setdefault(key, value)
        return response

    @app.exception_handler(sqlite3.Error)
    async def database_error(request: Request, exc: sqlite3.Error):
        return JSONResponse({'detail': 'Local report storage is unavailable; check the data directory and retry'}, status_code=503)

    def page(request, name, **context):
        token = request.cookies.get('csrf') or secrets.token_urlsafe(32)
        response = templates.TemplateResponse(request=request, name=name, context={'csrf': token, **context})
        response.set_cookie('csrf', token, httponly=True, samesite='strict')
        return response

    @app.get('/health')
    def health():
        with reports.connect() as db:
            db.execute('SELECT 1').fetchone()
        return {'status': 'ok', 'mode': 'local-single-user'}

    @app.get('/', response_class=HTMLResponse)
    def home(request: Request):
        return page(request, 'home.html', scans=reports.recent())

    @app.get('/scans/new', response_class=HTMLResponse)
    def new(request: Request):
        return page(request, 'new.html', error=None)

    @app.post('/scans')
    async def scan(request: Request):
        # Reject cross-origin browser posts before parsing untrusted uploads.
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            raise HTTPException(403, 'Cross-origin uploads are forbidden')
        if request.headers.get('sec-fetch-site') == 'cross-site':
            raise HTTPException(403, 'Cross-site uploads are forbidden')
        if scan_lock.locked():
            raise HTTPException(429, 'A local scan is already running; retry after it completes')
        async with scan_lock:
            try:
                async with request.form(max_files=2, max_fields=3, max_part_size=65536) as form:
                    csrf, cookie = form.get('csrf'), request.cookies.get('csrf')
                    if not isinstance(csrf, str) or not cookie or not hmac.compare_digest(csrf.encode('utf-8'), cookie.encode('utf-8')):
                        raise HTTPException(403, 'Invalid form token. Reload New scan and retry.')
                    wheel, source = form.get('wheel'), form.get('source')
                    prefix = form.get('source_prefix', '')
                    if not isinstance(wheel, UploadFile) or not isinstance(source, UploadFile) or not isinstance(prefix, str):
                        raise InputError('Provide a wheel, source ZIP and valid source prefix')
                    if not (wheel.filename or '').endswith('.whl') or not (source.filename or '').endswith('.zip'):
                        raise InputError('Expected a .whl artifact and a .zip source archive')
                    wheel_bytes = await wheel.read(MAX_ARCHIVE + 1)
                    source_bytes = await source.read(MAX_ARCHIVE + 1)
                    report = await run_in_threadpool(runner.run_sync, analyze, wheel_bytes, source_bytes,
                        artifact_name=wheel.filename or 'local.whl', source_prefix=prefix)
                    from .policy import apply_policy
                    report = apply_policy(report, reports.get_policy())
                    await run_in_threadpool(reports.save, report)
                return RedirectResponse(f'/scans/{report.scan_id}', status_code=303)
            except (InputError, OSError) as exc:
                response = page(request, 'new.html', error=str(exc))
                response.status_code = 422
                return response

    @app.get('/packages', response_class=HTMLResponse)
    def packages(request: Request, name: str = ''):
        with lookup_guard:
            now=time.monotonic()
            while lookup_times and now-lookup_times[0]>60:
                lookup_times.popleft()
            if len(lookup_times)>=20:
                raise HTTPException(429,'Package lookup limit reached; retry in a minute')
            lookup_times.append(now)
        from .pypi import project_versions
        project, error = None, None
        if name:
            try:
                project = project_versions(name)
            except (InputError, OSError) as exc:
                error = str(exc)
        return page(request, 'packages.html', project=project, error=error)

    @app.post('/scans/pypi')
    async def remote_scan(request: Request):
        from .pypi import scan_pypi
        origin = request.headers.get('origin')
        if (origin and origin != str(request.base_url).rstrip('/')) or request.headers.get('sec-fetch-site') == 'cross-site':
            raise HTTPException(403, 'Cross-origin scans are forbidden')
        if scan_lock.locked():
            raise HTTPException(429, 'A local scan is already running')
        async with scan_lock:
            async with request.form(max_files=0, max_fields=3, max_part_size=2048) as form:
                token, cookie = form.get('csrf'), request.cookies.get('csrf')
                if not isinstance(token, str) or not cookie or not hmac.compare_digest(token.encode(), cookie.encode()):
                    raise HTTPException(403, 'Invalid form token')
                try:
                    report = await run_in_threadpool(runner.run_sync, scan_pypi, form.get('name'), form.get('version'))
                    from .policy import apply_policy
                    report = apply_policy(report, reports.get_policy())
                    await run_in_threadpool(reports.save, report)
                except (InputError, OSError) as exc:
                    response = page(request, 'packages.html', project=None, error=str(exc))
                    response.status_code = 422
                    return response
        return RedirectResponse(f'/scans/{report.scan_id}', status_code=303)

    async def protected_fields(request, max_fields=3):
        if request.headers.get('origin') not in (None,str(request.base_url).rstrip('/')) or request.headers.get('sec-fetch-site')=='cross-site':
            raise HTTPException(403,'Cross-origin request forbidden')
        async with request.form(max_files=0,max_fields=max_fields,max_part_size=2048) as form:
            token,cookie=form.get('csrf'),request.cookies.get('csrf')
            if not isinstance(token,str) or not cookie or not hmac.compare_digest(token.encode(),cookie.encode()):
                raise HTTPException(403,'Invalid form token')
            return dict(form)

    @app.post('/jobs/pypi')
    async def queue_pypi(request: Request):
        from .pypi import package_name,version_name
        form=await protected_fields(request)
        try:
            payload={'name':package_name(form.get('name')),'version':version_name(form.get('version'))}
            job_id=runner.submit('pypi',payload)
        except InputError as exc:
            raise HTTPException(429 if 'queue' in str(exc) else 422,str(exc)) from exc
        return RedirectResponse('/jobs/'+job_id,status_code=303)

    @app.post('/jobs/ai')
    async def queue_ai(request: Request):
        form=await protected_fields(request,2)
        report=lookup(str(form.get('scan_id','')))
        try:
            job_id=runner.submit('ai',{'scan_id':report.scan_id})
        except InputError as exc:
            raise HTTPException(429,str(exc)) from exc
        return RedirectResponse('/jobs/'+job_id,status_code=303)

    def lookup_job(job_id):
        if not re.fullmatch('[a-f0-9]{32}',job_id):
            raise HTTPException(404,'Job not found')
        job=runner.get(job_id)
        if not job: raise HTTPException(404,'Job not found')
        return job

    @app.get('/jobs/{job_id}',response_class=HTMLResponse)
    def job_page(request: Request,job_id: str):
        return page(request,'job.html',job=lookup_job(job_id))

    @app.get('/jobs/{job_id}/status')
    def job_status(job_id: str):
        return lookup_job(job_id)

    @app.get('/watchlist',response_class=HTMLResponse)
    def watchlist_page(request: Request):
        return page(request,'watchlist.html',watched=reports.watchlist(),events=reports.watch_events(),results=None)

    @app.post('/watchlist')
    async def add_watched(request: Request):
        form=await protected_fields(request,2)
        try: reports.add_watch(form.get('name'))
        except InputError as exc: raise HTTPException(422,str(exc)) from exc
        return RedirectResponse('/watchlist',status_code=303)

    @app.post('/watchlist/check',response_class=HTMLResponse)
    async def check_watched(request: Request):
        from .watch import watch_once
        await protected_fields(request,1)
        if scan_lock.locked(): raise HTTPException(429,'Investigation in progress')
        async with scan_lock:
            results=await run_in_threadpool(runner.run_sync,watch_once,reports)
        return page(request,'watchlist.html',watched=reports.watchlist(),events=reports.watch_events(),results=results)

    @app.get('/policy', response_class=HTMLResponse)
    def policy_settings(request: Request):
        return page(request, 'policy.html', config=reports.get_policy(), error=None)

    @app.post('/policy')
    async def update_policy(request: Request):
        from .policy import PolicyConfig
        if request.headers.get('origin') not in (None, str(request.base_url).rstrip('/')):
            raise HTTPException(403, 'Cross-origin request forbidden')
        async with request.form(max_files=0, max_fields=5, max_part_size=2048) as form:
            token, cookie=form.get('csrf'),request.cookies.get('csrf')
            if not isinstance(token,str) or not cookie or not hmac.compare_digest(token.encode(),cookie.encode()):
                raise HTTPException(403,'Invalid form token')
            config=PolicyConfig(**{key:key in form for key in PolicyConfig.model_fields})
            reports.save_policy(config)
        return RedirectResponse('/policy',status_code=303)

    @app.get('/scans/{scan_id}/report.html', response_class=HTMLResponse)
    def html_export(scan_id: str):
        from .capsule import capsule_html
        return HTMLResponse(capsule_html(lookup(scan_id)),headers={'Content-Disposition':f'attachment; filename="pkgtruth-{scan_id}.html"', 'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"})

    @app.post('/scans/{scan_id}/dna')
    async def dna_comparison(request: Request, scan_id: str):
        from .dna import compare_releases
        if request.headers.get('origin') not in (None, str(request.base_url).rstrip('/')):
            raise HTTPException(403, 'Cross-origin request forbidden')
        async with request.form(max_files=0, max_fields=2, max_part_size=2048) as form:
            token, cookie = form.get('csrf'), request.cookies.get('csrf')
            if not isinstance(token, str) or not cookie or not hmac.compare_digest(token.encode(), cookie.encode()):
                raise HTTPException(403, 'Invalid form token')
            baseline = lookup(str(form.get('baseline', '')))
        try:
            report = await run_in_threadpool(runner.run_sync, compare_releases, baseline, lookup(scan_id))
        except InputError as exc:
            raise HTTPException(422, str(exc)) from exc
        await run_in_threadpool(reports.save, report)
        return RedirectResponse(f'/scans/{scan_id}', status_code=303)

    @app.post('/scans/{scan_id}/investigate')
    async def ai_investigation(request: Request, scan_id: str):
        from .investigator import investigate
        if request.headers.get('origin') not in (None, str(request.base_url).rstrip('/')) or request.headers.get('sec-fetch-site') == 'cross-site':
            raise HTTPException(403, 'Cross-origin requests forbidden')
        async with request.form(max_files=0, max_fields=1, max_part_size=2048) as form:
            token, cookie = form.get('csrf'), request.cookies.get('csrf')
            if not isinstance(token, str) or not cookie or not hmac.compare_digest(token.encode(), cookie.encode()):
                raise HTTPException(403, 'Invalid form token')
        if scan_lock.locked():
            raise HTTPException(429, 'An investigation is already running')
        async with scan_lock:
            report = await run_in_threadpool(runner.run_sync, investigate, lookup(scan_id))
            await run_in_threadpool(reports.save, report)
        return RedirectResponse(f'/scans/{scan_id}', status_code=303)

    def lookup(scan_id):
        if not re.fullmatch('[a-f0-9]{32}', scan_id):
            raise HTTPException(404, 'Report not found')
        report = reports.get(scan_id)
        if report is None:
            raise HTTPException(404, 'Report not found')
        return report

    @app.get('/scans/{scan_id}', response_class=HTMLResponse)
    def result(request: Request, scan_id: str):
        report = lookup(scan_id)
        return page(request, 'result.html', report=report, evidence_lookup={item.id: item for item in report.evidence}, baselines=[r for r in reports.recent() if r.scan_id != scan_id and r.release_fingerprint and (not report.package_name or not r.package_name or r.package_name == report.package_name)])

    @app.get('/scans/{scan_id}/report.json')
    def export(scan_id: str):
        return JSONResponse(lookup(scan_id).model_dump(mode='json'), headers={
            'Content-Disposition': f'attachment; filename="pkgtruth-{scan_id}.json"'})

    return app


app = create_app()

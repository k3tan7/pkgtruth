"""Loopback-only local web interface; calls the same service as the CLI."""
from __future__ import annotations

import asyncio
import hmac
import re
import secrets
import sqlite3
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
    app = FastAPI(title='pkgtruth', version='0.1.0', docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', '[::1]', 'testserver'])
    app.add_middleware(LocalBoundary)
    app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')
    templates = Jinja2Templates(directory=ROOT / 'templates')
    reports = store or ReportStore()
    scan_lock = asyncio.Lock()

    @app.middleware('http')
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update({
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
        })
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
                    report = await run_in_threadpool(analyze, wheel_bytes, source_bytes,
                        artifact_name=wheel.filename or 'local.whl', source_prefix=prefix)
                    await run_in_threadpool(reports.save, report)
                return RedirectResponse(f'/scans/{report.scan_id}', status_code=303)
            except (InputError, OSError) as exc:
                response = page(request, 'new.html', error=str(exc))
                response.status_code = 422
                return response

    def lookup(scan_id):
        if not re.fullmatch('[a-f0-9]{32}', scan_id):
            raise HTTPException(404, 'Report not found')
        report = reports.get(scan_id)
        if report is None:
            raise HTTPException(404, 'Report not found')
        return report

    @app.get('/scans/{scan_id}', response_class=HTMLResponse)
    def result(request: Request, scan_id: str):
        return page(request, 'result.html', report=lookup(scan_id))

    @app.get('/scans/{scan_id}/report.json')
    def export(scan_id: str):
        return JSONResponse(lookup(scan_id).model_dump(mode='json'), headers={
            'Content-Disposition': f'attachment; filename="pkgtruth-{scan_id}.json"'})

    return app


app = create_app()

"""Browser request boundary and safe HTML/API error negotiation."""
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent / 'templates')


def canonical_origin(value):
    """Compare scheme, host and effective port, never hostname aliases."""
    try:
        if not value or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
        return parsed.scheme, parsed.hostname.lower(), port
    except ValueError:
        return None


def same_origin_request(scope):
    headers = scope.get('headers', [])
    origins = [v.decode('latin1') for k, v in headers if k == b'origin']
    hosts = [v.decode('latin1') for k, v in headers if k == b'host']
    if len(hosts) != 1 or len(origins) > 1:
        return False
    if any(k == b'sec-fetch-site' and v == b'cross-site' for k, v in headers):
        return False
    expected = canonical_origin(scope.get('scheme', 'http') + '://' + hosts[0])
    # Non-browser clients may omit Origin but still must pass the form CSRF check.
    return expected is not None and (not origins or canonical_origin(origins[0]) == expected)


def wants_html(request):
    path = request.url.path
    return ('text/html' in request.headers.get('accept', '') and path != '/health'
            and not path.endswith(('/status', '.json')))


def error_response(request, status, detail, headers=None):
    if not wants_html(request):
        return JSONResponse({'detail': detail}, status_code=status, headers=headers)
    titles = {400: 'This request could not be read', 403: 'Reload this form to continue',
              404: 'We could not find that page', 413: 'These files are too large',
              422: 'Check your input and try again', 429: 'Please wait before trying again',
              500: 'Something went wrong', 503: 'Local storage is unavailable'}
    path = request.url.path
    recovery = '/policy' if path.startswith('/policy') else '/watchlist' if path.startswith('/watchlist') else '/packages' if path.startswith(('/packages', '/jobs')) else '/scans/new' if path == '/scans' else '/'
    return TEMPLATES.TemplateResponse(request=request, name='error.html', context={
        'status': status, 'error_title': titles.get(status, 'We could not complete that request'),
        'detail': detail, 'recovery_url': recovery,
    }, status_code=status, headers=headers)

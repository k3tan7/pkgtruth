"""Public HTTPS allowlist, redirect/DNS checks and bounded streaming downloads."""
import ipaddress
import json
import socket
from time import monotonic
from urllib.parse import urlsplit

import httpx

from .inputs import InputError, MAX_ARCHIVE

HOSTS = {'pypi.org', 'files.pythonhosted.org', 'api.github.com', 'codeload.github.com'}


def public_addresses(host):
    return {entry[4][0] for entry in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}


class Fetcher:
    def __init__(self, *, transport=None, resolver=public_addresses):
        self.resolver = resolver
        self.client = httpx.Client(transport=transport, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(15, connect=5), headers={'User-Agent': 'pkgtruth/0.3 local-integrity-investigator', 'Accept-Encoding': 'identity'})

    def close(self):
        self.client.close()

    def validate(self, url):
        parsed = urlsplit(url)
        try:
            valid = parsed.scheme == 'https' and parsed.hostname in HOSTS and parsed.port in (None, 443) and not parsed.username and not parsed.password and not parsed.fragment
        except ValueError:
            valid = False
        if not valid:
            raise InputError('Network destination is outside the approved public HTTPS sources')
        addresses = self.resolver(parsed.hostname)
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise InputError('Network destination resolves to a non-public address')

    def get(self, url, limit=MAX_ARCHIVE):
        started = monotonic()
        try:
            for _ in range(4):
                if monotonic() - started > 45:
                    raise InputError('Download time limit exceeded')
                self.validate(url)
                with self.client.stream('GET', url) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get('location')
                        if not location:
                            raise InputError('Redirect has no destination')
                        url = str(response.url.join(location))
                        continue
                    if response.status_code == 404:
                        raise FileNotFoundError('Requested registry/repository resource does not exist')
                    response.raise_for_status()
                    length = response.headers.get('content-length')
                    if length is not None and (not length.isascii() or not length.isdigit() or len(length) > 12 or int(length) > limit):
                        raise InputError('Download Content-Length exceeds limit or is invalid')
                    if response.headers.get('content-encoding', 'identity') != 'identity':
                        raise InputError('Encoded HTTP bodies are unsupported; identity encoding is required')
                    body = bytearray()
                    for chunk in response.iter_bytes(65536):
                        if monotonic() - started > 45 or len(body) + len(chunk) > limit:
                            raise InputError('Download byte/time limit exceeded')
                        body.extend(chunk)
                    return bytes(body)
            raise InputError('Too many network redirects')
        except httpx.HTTPStatusError as exc:
            raise InputError(f'Approved source returned HTTP {exc.response.status_code}') from exc
        except (httpx.HTTPError, OSError, ValueError) as exc:
            if isinstance(exc, (InputError, FileNotFoundError)):
                raise
            raise InputError(f'Approved-source request failed ({type(exc).__name__})') from exc

    def json(self, url):
        try:
            return json.loads(self.get(url, 2 * 1024 * 1024))
        except (UnicodeError, ValueError) as exc:
            if isinstance(exc, InputError):
                raise
            raise InputError('Remote metadata is not valid JSON') from exc

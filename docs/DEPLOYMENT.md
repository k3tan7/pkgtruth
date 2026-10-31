# Local deployment

Requires Python 3.12 or newer. Run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
python examples/generate.py
pkgtruth serve --port 8000
```

Open http://127.0.0.1:8000 directly in a normal browser. Sandboxed embedded browsers that send `Origin: null` are intentionally rejected for uploads. Use examples/clean.whl or examples/tampered.whl with examples/source.zip. Source prefix is blank for these fixtures.

`PKGTRUTH_DATA_DIR` selects the local report directory (default `.pkgtruth` relative to the launch directory). The store contains code excerpts; protect it as sensitive data. Stop the server before deleting this directory to clear stored scans. Raw uploads are discarded after processing.

The server is intentionally loopback-only, single-user, with no authentication. It rejects remote HTTP clients and does not trust proxy forwarding for access control. Do not expose it through a tunnel, reverse proxy or public container mapping. A source ZIP must be within the documented archive limits. Source-directory inspection is available only in the CLI.

## Not production ready

Public deployment is deferred. Required work includes authentication, authorization, per-user report isolation, CSRF/session review for authenticated use, request-rate limits, isolated durable workers with hard memory/CPU/deadline controls, database migrations, retention, audit logging, TLS, load/recovery testing and deployment rollback. Docker/Compose is deferred until an isolated service configuration can preserve the local access boundary. Health route: `/health`.

Current web uploads keep their request open during bounded inspection. No durable jobs or background scan progress are claimed. Run a single process for the local scan concurrency limit. Never expose Ollama publicly if future milestones add it.

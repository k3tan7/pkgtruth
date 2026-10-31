# Private deployment

Requires Python 3.12+. Follow the README virtualenv installation and launch `pkgtruth serve --port 8000`. The service binds only 127.0.0.1 and rejects remote clients, untrusted Host headers and cross-origin mutations. Access directly from a normal browser. Never publish through a tunnel or reverse proxy.

`PKGTRUTH_DATA_DIR` selects the SQLite report/job/watch/settings directory, default `.pkgtruth` relative to launch. Reports include bounded source excerpts and model output. Protect directory permissions and backups; stop the service before copying or deleting its database. Raw package/source downloads and uploads are held only during processing and discarded, not installed or executed. Report/job history has no automatic retention cleanup; watch observations retain the latest 200 entries. Removing a watched package is available through the CLI. Deleting the data directory intentionally resets all stored state.

Health: `GET /health` checks local database access. PyPI/AI jobs persist QUEUED/RUNNING/COMPLETE/FAILED status, with at most two unfinished jobs and one worker. On restart unfinished jobs become INTERRUPTED; resubmit manually. This is single-process persistence, not reliable distributed execution. Run one application process per database. Do not start CLI writers concurrently with the web service when investigating the same report: deterministic scan IDs intentionally update that report's AI/DNA annotations.

## Private Ollama

Run Ollama on the deployment host/private machine and provision the exact `qwen3.5:4b` digest recorded in HACKATHON.md. The server does not download models. Set `PKGTRUTH_OLLAMA_URL=http://127.0.0.1:11434` (default). Permitted private host spellings also include `localhost`, `[::1]`, `ollama` and `host.docker.internal`, port 11434 only; no credentials, paths or arbitrary public URLs. Container hostnames must resolve inside a trusted private network. Do not expose Ollama to the Internet. A remote production host cannot assume it can reach the developer's Mac.

AI is optional. Unavailable API, wrong digest, oversized/malformed JSON and invalid evidence references remain explicit failure states. Deterministic scans and policy checks continue without a model. Metadata requests time out after 5s and generation after 120s; response size and prompt context are bounded. The actual license/runtime metadata is recorded per investigation; allowlisted evidence IDs do not prove model statements correct.

## Docker configuration (not executed here)

Docker is unavailable on the development machine, so image building, Compose startup and container health checks are **not verified**. Provided configuration targets a private **Linux host**:

```sh
docker compose build
docker compose up -d
docker compose logs pkgtruth
```

`compose.yaml` uses Linux host networking to retain the application loopback boundary, not a public port mapping. The image runs as UID 10001, stores reports in `/data`, uses a read-only root, bounded `/tmp`, dropped capabilities, resource limits and a loopback HTTP health check. Host networking on other platforms requires explicit support; no portable desktop-container claim is made. Inspect the configuration and verify volume ownership, private Ollama availability, limits and health on the actual host before using it. The Docker base tag and dependencies are version ranges, not a reproducibly pinned production supply chain.

## Operational acceptance and remaining blockers

Verified locally: virtual archive/AST limits, no target execution, bounded approved-host HTTPS with DNS/private-address checks, digest/size checks, HTML escaping/CSP, local access/origin/CSRF boundaries, exact-name lookup rate limiting (20/minute), queue capacity, database-backed status and duplicate-suppressed watch observations. Heavy analysis is serialized; limits are cooperative and no hard process sandbox is claimed.

Before public multi-user deployment, implement and independently verify authentication, authorization, per-user scan isolation, isolated cancellable workers, robust queue leases/retries, proxy/TLS configuration, aggregate upload/concurrency limits, migrations, retention, operational monitoring, backup/restore and load/adversarial acceptance. PostgreSQL and external alerting are not implemented. Do not bypass the current local boundary to simulate production readiness.

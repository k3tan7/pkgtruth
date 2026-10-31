# Test evidence — milestone 1

Executed locally on 2026-11-01, on `feat/local-analysis`. No target package code was installed, imported, built or executed.

## Automated checks

| Command | Observed result |
| --- | --- |
| `.venv/bin/pip install -e '.[test]'` | Installed project and declared dependencies; initial sandbox DNS failure resolved through the approved network boundary. |
| `.venv/bin/python -m pytest -q` | **51 passed**, 1 upstream Starlette/httpx deprecation warning, Python **3.14.6**, 0.58s. |
| `.venv/bin/python -m build --no-isolation` | Built source distribution and wheel from that source distribution successfully. |
| `/private/tmp/pkgtruth-py312-verify/bin/pip install --no-deps --force-reinstall dist/pkgtruth-0.1.0-py3-none-any.whl` | Installed the built wheel into a separate Python **3.12.15** virtualenv with declared test dependencies. |
| From `/private/tmp`: `/private/tmp/pkgtruth-py312-verify/bin/python -m pytest /Users/ketan/pkgtruth/tests -q` | **51 passed**, same upstream deprecation warning, **0.50s**; imports use installed wheel, with no source-path pytest configuration. |
| `pkgtruth --help`, `pkgtruth --version` in installed 3.12 environment | CLI available; version **0.1.0**. |
| `python -m pip check` | No broken requirements found. |
| Archive inspection of built distributions | Wheel includes templates and static assets; source distribution includes `tests/conftest.py`. |
| `python examples/generate.py` | Generated actual deterministic fixtures, report outputs and JSON schema. CI verifies regeneration produces no diff. |
| `git diff --check` | Passed before commit. |

Tests cover clean/tampered comparisons, hashes, added/removed/modified/identical and binary files, explicit src layouts, ambiguous/no-overlap mappings, unsupported .data relocation, schema validation, stable evidence references, packaging-metadata uncertainty, bounded previews, malformed/CRC-corrupt ZIPs, traversal, NUL paths, special/archive links, source hardlinks/symlinks/FIFOs, normalized and parent-path collisions, byte/count/compression/time limits, non-execution sentinel, installed CLI exits/exports, web multipart uploads, CLI/web equality, HTML escaping, CSRF and null/cross-origin rejection, upload limits, local access/host restrictions, missing reports and explicit storage failures.

The first run had eight failures because a broad ValueError handler replaced specific InputError explanations. Fixed the handler to preserve explicit rejection reasons; the tests were not weakened.

## Running-server and UI verification

Started `pkgtruth serve --port 8000` on **127.0.0.1 only**. The initial sandbox bind was denied; the authorized local-server boundary allowed it.

Ran `.venv/bin/python scripts/verify_running.py` against that real server:

- Clean fixture: POST **303**, stored JSON **200**, rendered results **200**, exact engine-report equality.
- Tampered fixture: POST **303**, stored JSON **200**, rendered results **200**, exact engine-report equality.
- Clean scan: `c54021efc732bb7b07086a2b045174a0`.
- Tampered scan: `ee29a2414bfd0618082177d59fce129a`.

The browser rendered home, new scan and the actual stored tampered results. Searching `demo/message.py`, selecting Modified and expanding the result showed **1 shown**, both SHA-256 hashes, evidence `E-7be508c51f2bde21`, and the expected reviewed-source/changed-after-review unified diff. Captured results screenshot. Browser console returned no warnings/errors for the results page. At a 390px viewport, document client and scroll widths were both 390px (no page-level horizontal overflow); restored the original viewport afterward.

Embedded-browser form submission was **rejected with 403**. A temporary diagnostic server confirmed it sends `Origin: null`, so the real CSRF/origin policy rejects it. No security bypass was added. Normal same-origin uploads were verified over real HTTP with the actual form token/cookie using `scripts/verify_running.py`; full mouse-driven upload in a normal external browser remains an unverified manual check. Native browser access timed out in the available automation environment. Open the app directly in your normal browser for uploads. The temporary diagnostic server is not part of the product.

## Limits

- [PR #2](https://github.com/k3tan7/pkgtruth/pull/2) is open. GitHub Actions [run 41232943558](https://github.com/k3tan7/pkgtruth/actions/runs/41232943558) completed successfully for implementation commit `6303c911386d5694cc7b3f5a15707823941075e2`. Verified successful distribution build, installed-wheel tests outside the checkout, CLI/app checks, and deterministic examples/schema regeneration. Documentation changes afterward require their own current-head checks; the PR remains at the human review/merge gate.
- Real PyPI retrieval, RECORD/provenance verification, behavior analysis, historical DNA, policy checks, local Ollama inference and production security are not implemented or tested in milestone 1.
- Limits are cooperative, checked between bounded operations; hard process isolation and durable jobs remain future work.
- The upstream TestClient deprecation warning does not fail tests; no warning filter hides it.

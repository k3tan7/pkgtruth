# Reproducible offline investigations

These are inert synthetic package inputs, not malware samples. The generator creates real ZIP/wheel-shaped artifacts with deterministic timestamps, valid RECORD entries, and actual engine-generated report outputs. The short `clean.whl` / `tampered.whl` filenames are demo labels, not installable wheel filenames. Never install or execute investigation targets.

```sh
python examples/generate.py
pkgtruth scan local --wheel examples/clean.whl --source examples/source.zip --json
# exit 0: two matching source files; three informational generated metadata files
pkgtruth scan local --wheel examples/tampered.whl --source examples/source --json
# exit 1: one changed source file and one unexpected artifact file
```

The web app accepts the same wheel and `source.zip`; leave the source prefix blank. The results match the committed `*.report.json` outputs (when the same artifact filename is supplied).

The tampered fixture changes an ordinary string and adds an inert variable; it does not simulate execution or prove malicious behavior. Its RECORD is internally consistent, demonstrating why comparison with independent source matters. RECORD validation itself is deferred to milestone 2.

`generate.py` uses pkgtruth's real shared engine and also writes `docs/report.schema.json`. Run it again and check `git diff -- examples docs/report.schema.json` to verify reproducibility. Source ZIP and source directory contain exactly the same relative files and bytes.

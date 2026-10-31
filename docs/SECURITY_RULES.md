# Static security rules — milestone 2

All checks run inside the shared analysis service. No target code, hooks, scripts, build backends or tests are imported, installed or executed. Findings are review evidence, not attack verdicts.

## RECORD consistency

The [PyPA wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/#the-dist-info-directory) requires hashes for wheel members except RECORD itself and legacy signature files. RECORD's own row has no self-hash; legacy RECORD.jws/p7s files are not listed. Weak digests are forbidden.

pkgtruth checks exact CSV paths, duplicate/normalized aliases, missing and unlisted files, self-entry, declared sizes and canonical unpadded URL-safe base64 digests. Supported algorithms: sha256/384/512, sha3_256/384/512, blake2b/s. Unsupported algorithms are UNRESOLVED, not silently accepted. Insecure md5/sha1/sha224, malformed CSV and inconsistencies are INVALID. No RECORD is UNAVAILABLE. Multiple top-level distribution roots/RECORDs are INVALID. Parser limits produce UNRESOLVED. The [RECORD format permits omitted sizes](https://packaging.python.org/en/latest/specifications/recording-installed-packages/#the-record-file); pkgtruth conservatively reports UNRESOLVED size coverage for those rows, rather than alleging an invalid size. A declared self-entry size is checked if present. This is a consistency check, not a full wheel-format validator.

INVALID produces a HIGH finding. Missing/unresolved checks produce MEDIUM findings. Any non-VALID result makes analysis PARTIAL and CLI exit 1. **VALID is not provenance or a safety verdict**: an attacker can rewrite RECORD after changing code. Signatures are not verified; provenance stays NOT_CHECKED.

## Startup surfaces and AST indicators

The [Python site documentation](https://docs.python.org/3.12/library/site.html) identifies import directives in .pth files and customization modules as startup mechanisms. Actual activation depends on installation location and Python configuration.

- PTH_EXECUTION: only lines starting at column zero with `import ` or `import\t`, in a root-level .pth file or a corresponding .data/purelib or platlib root. Comments, plain paths, leading whitespace and nested .pth files are not claimed to be automatic hooks.
- CUSTOMIZE_MODULE: root sitecustomize/usercustomize .py modules or packages, including .data relocation candidates. .data byte mapping remains unsupported and PARTIAL.
- NETWORK_CAPABILITY / SUBPROCESS_CAPABILITY: recognized module imports and direct syntactic references/calls, including import aliases.
- DYNAMIC_EXECUTION / DYNAMIC_IMPORT: supported exec/eval/compile/__import__/importlib.import_module call shapes.
- NATIVE_BINARY / BYTECODE: binary magic/suffixes or .pyc files; no disassembly, decompilation or execution.

Each indicator has a location, bounded context, stable ID, existing evidence references and relation to the explicitly mapped source: NEW, PRESENT, SOURCE_ONLY or UNKNOWN. Line movement alone does not create a new capability. A new startup surface is HIGH; other new/unknown capabilities are MEDIUM; unchanged capabilities are INFORMATIONAL. Source-only indicators are inventory, not evidence of installed behavior.

Aliases are resolved syntactically across the file. Local modules, rebinding, shadowing, control flow, reachability, reflection and arbitrary indirect calls are not resolved. An import named requests does not prove a network request. Strings/comments are not scanned as executable Python syntax. Python encoding cookies are respected for AST parsing; excerpts decode non-UTF-8 bytes with replacement.

## Declarations and normal build differences

The engine compares in-scope static pyproject.toml project dependencies/scripts, PKG-INFO or matching .dist-info metadata. Exact paths win; otherwise a single candidate source declaration is required. Multiple candidates, dynamic fields, legacy build-only TOML or unavailable metadata leave the comparison UNKNOWN. Source metadata outside the user-selected prefix is not used. No setup.py/build backend is invoked.

Dependency comparison uses sorted raw declared requirement strings, not dependency resolution or semantic version normalization. Formatting differences can require review. Entry-point names/targets are compared as declarations. Missing entry-point files with distribution metadata yield empty declarations, so removed scripts can be detected. An unknown nonempty script declaration requires review. Dependency changes and changed scripts are MEDIUM. No claim is made that an entry point ran or a dependency was installed.

Known generated metadata names and license/SBOM directories are classified as packaging metadata, with explicit uncertainty. Arbitrary .py/.pth/.pyc content does not get a metadata exemption. Metadata content still receives RECORD, parser and capability checks. Source-only root pyproject.toml, setup.py/setup.cfg, MANIFEST.in and PKG-INFO receive informational packaging_configuration classification with an explicit unverified-omission explanation. Added/modified copies receive no exemption. Other build transformations, including compiled code, remain unexplained; no blanket generated-code allowance exists.

## Bounds and coverage

On top of archive limits, parsers allow 128 KiB per Python/PTH file, 20,000 AST nodes per file, 2,000 reported indicators total, 128 KiB cumulative metadata per side, 256 declared values per side, 128 metadata comparisons and 1,003 RECORD rows. These are cooperative bounds under the existing cumulative 30-second deadline. Oversized/invalid Python or metadata, parser failures and exhausted budgets produce PARTIAL with limitations. Record issues and code-context evidence stay bounded. Production still needs isolated workers with OS resource limits.

Schema 1.1 adds record_check, behavior_indicators and metadata_changes. Existing schema 1.0 reports remain readable with NOT_CHECKED/empty defaults and preserve their original fields on export; stored results are not rerun or upgraded into verified claims. New scan IDs include static-security-2, keeping them distinct from earlier byte-only scans.

## Network, model and historical layers (schema 1.2)

Registry access is approved-host public HTTPS only, with public-address DNS checks, bounded redirects, 2 MiB metadata / 16 MiB artifacts, size/digest verification and no source builds. GitHub release correspondence is unverified; unresolved source produces artifact-only PARTIAL coverage. Wheel identity must match the requested project/version.

Private Ollama is separate from public retrieval. It uses a fixed private endpoint allowlist and pinned digest, bounded context/output, structured schemas and evidence-reference validation. Prompt injection is treated as untrusted package text; validation does not guarantee a model's reasoning correct. Deterministic fields and policy remain unchanged on success or failure.

DNA compares bounded fingerprints against a selected stored/retrieved artifact; first-observed means relative to that baseline only. Impact edges are conditional static relationships. Policies never interpret AI output. Capsules escape package/model text. Watch events describe observed registry metadata changes, not confirmed malicious releases. Worker threads and parser/network deadlines are cooperative; hard sandboxing and public multi-user service security are not implemented.

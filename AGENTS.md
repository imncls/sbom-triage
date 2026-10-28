# Agent Guidelines

sbom-triage is a command-line tool (`sbom_triage.py`) that reads CycloneDX JSON SBOMs (a single file or every SBOM in a directory), looks up known vulnerabilities in OSV, enriches them with CISA KEV and EPSS, and prioritizes them. It is meant to support other tools.

The tool only generates results. It does not store them or compare runs; that belongs to whatever system consumes its JSON output. Do not add persistence of results.

## General

- Read this file before making changes.
- Inspect the existing code before implementing new functionality.
- Prefer small, focused changes over large rewrites.
- Do not modify unrelated code.
- Reuse existing abstractions when appropriate.
- Avoid unnecessary dependencies and abstractions.
- If an architectural decision is required, prefer the simplest maintainable solution.
- Do not implement features that have not been requested.

## Code quality

- Follow PEP 8 and standard Python conventions. `ruff` is the formatter and linter when available.
- Use type hints on public functions. Use dataclasses for domain models.
- Keep parsing, data sources (HTTP and cache), prioritization, and output separated.
- Prefer small, cohesive functions.
- Avoid duplicated logic.
- Use meaningful names rather than comments to explain code.
- Add comments only when they explain non-obvious decisions.
- Handle errors explicitly. No bare `except:` and no `except Exception: pass`; do not silently swallow exceptions.
- Do not show raw exceptions or stack traces to users. Raise `SbomError` (or `NotAnSbomError`) or `ApiError` (or `NotFoundError`) with a short, app-authored message; `main` turns them into an error line and exit code 1.
- Everything in the repository is written in English, with no exceptions: code comments, docstrings, identifiers, program output (log messages, errors, table, priority names, `--fail-on` values), tests, test data, file names, README, AGENTS.md, and any other documentation.

## Security

- Security is a first-class requirement and must be considered in every implementation.
- Follow established security best practices and, where applicable, recognized guidance such as OWASP and NIST.
- Treat all external input as untrusted: SBOMs and any other file in an input directory (including their names), cache files, and every response from OSV, CISA KEV, and FIRST EPSS.
- Validate at trust boundaries:
  - Vulnerability IDs must match `VULN_ID_RE` before they are used. They are percent-encoded in URLs and never used as file names: cache files are named by a SHA-256 hash of the ID (`_cache_name`). Some valid OSV IDs contain `:`.
  - CVE IDs must match `CVE_RE` before they are sent to EPSS or used as keys.
  - Strip control and invisible characters (`clean`: Unicode categories Cc, Cf, Zl, Zp, which include bidirectional overrides) from any external string before printing it, so data cannot inject terminal escape sequences or disguise output. Never put such characters literally in source files; use escape sequences.
  - Identify SBOMs by content (`read_sbom`), never by file name. Sniff the first bytes before loading a file. There is deliberately no size limit for SBOMs: a file that does not fit in memory is reported, never a crash. HTTP responses keep their size limit. Avoid unbounded recursion over nested components.
  - In directory mode, read only regular files directly inside the input directory; do not follow symlinks or descend into subdirectories.
- Only call the fixed HTTPS endpoints defined as constants, and only follow redirects to HTTPS (`_HttpsOnlyRedirectHandler`). Do not add new network destinations without being asked.
- Never hardcode secrets, tokens, or credentials. The current APIs need none; if one is ever added, read it from the environment and never log it.
- Do not use `eval`, `exec`, `pickle`, or `shell=True`.
- Write files (cache, JSON reports) atomically, only inside the paths the user chose or the cache directory. Output file names are derived from input file names, never from SBOM content.
- Results must never be silently incomplete. A failing data source is an error (exit code 1); do not fall back to stored data. In directory mode, a file that may be a CycloneDX SBOM but cannot be analyzed is an error (`SbomError`, exit code 4), while a file that is not a CycloneDX SBOM is skipped (`NotAnSbomError`). The only data left out with just a warning is an OSV record that no longer exists (HTTP 404), because there is nothing to report.
- Apply the principle of least privilege. The tool needs no administrator rights.
- Do not disable security mechanisms (such as TLS verification) to work around development problems.
- When a requested implementation conflicts with a security best practice, prefer the secure implementation and clearly explain the trade-off.

## External resources

- Data sources: OSV (`api.osv.dev`), CISA KEV (`cisa.gov`), FIRST EPSS (`api.first.org`).
- All HTTP goes through `HttpClient`: custom User-Agent, timeout, retries with exponential backoff on 429, 5xx, and network errors, honoring `Retry-After`.
- Respect the services: batch requests (OSV 1000 queries, EPSS 100 CVEs), and do not add aggressive concurrency.
- Freshness matters more than saving requests: OSV queries, KEV, and EPSS are fetched on every run. Only OSV vulnerability details are cached (`.cache/osv/`), and they are re-fetched when OSV reports a newer `modified` date.
- Handle failures explicitly: timeouts, rate limits, malformed or unexpected JSON, pagination that never ends.

## Testing

After meaningful changes, run from the project root:

```
python -m unittest
```

Add or update tests for business-critical behavior. Prioritize:

- SBOM and purl parsing (nested components, missing purl or version)
- CVSS score calculation (v4.0 results must match the FIRST reference calculator)
- SBOM detection by content and directory mode
- prioritization rules
- duplicate grouping and malware detection
- HTTP retries and pagination
- input validation of external data
- bug fixes

Test rules:

- Tests must not use the network. Inject a fake opener into `HttpClient` or a fake client into the functions under test.
- Use small synthetic SBOMs and API responses built inside the tests.

## Formatting

If `ruff` is installed, before finishing a task run:

```
python -m ruff format .
python -m ruff check .
```

Keep formatting consistent with the existing project.

## Git

- Keep changes focused and reviewable.
- Do not modify unrelated files.
- Do not remove existing functionality without a reason.
- Avoid unnecessary refactors while implementing a feature.
- Do not commit generated files, secrets, credentials, or local configuration.
- `.gitignore` must cover at least: `.cache/`, `.venv/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`. Exported results may reveal what a system runs; do not commit them.
- Run `git status` before committing and check the file list for credentials, exported results, or local machine paths.
- Keep the documentation current: `README.md` for people who use the tool (what it does, usage, supported formats, prioritization rules, scoring sources, data sources) and `CONTRIBUTING.md` for people who work on it (setup, running from source, structure, tests, CVSS reference checks, validation with real SBOMs, data source assumptions, versioning).
- The version lives in `__version__` in `sbom_triage.py`. `FORMAT_VERSION` is the JSON report format version: increase it on any incompatible change to the reports and document the fields in the README.
- Scoring code must cite its source. The CVSS v2/v3 tables and equations come from the FIRST specifications, and the CVSS v4.0 section is a port of the FIRST reference calculator (BSD-2-Clause): keep the source URLs, the copyright notice, and the license text, and keep the README "Scoring sources" section in sync.

## Security reviews

- For security-sensitive changes, perform an appropriate security review before considering the work complete.
- Use automated security tooling where available.
- Do not automatically apply security fixes without reviewing their impact.
- Treat security findings as hypotheses that must be validated before making significant changes.

## Dependencies

- Runtime uses the Python standard library only. Do not add runtime dependencies without being asked.
- Development tools (`ruff`, optionally `pytest`) are not required to run the tool.
- Before adding any dependency, check its maintenance status, security history, and license, and pin it.

## Before finishing

Check:

- Does the implementation match the requested behavior?
- Did I preserve existing functionality?
- Did I introduce unnecessary complexity?
- Did I add appropriate tests?
- Do the tests pass?
- Does `ruff check` pass (if available)?
- Did I accidentally modify unrelated files?
- Is `README.md` still accurate?

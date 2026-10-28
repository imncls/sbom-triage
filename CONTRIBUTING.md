# Contributing to sbom-triage

This guide is for people who work on `sbom_triage.py`. For what the tool does and
how to use it, see [README.md](README.md). The project rules that every change must
follow are in [AGENTS.md](AGENTS.md); this guide summarizes them but AGENTS.md is
the reference.

## Requirements

- Python 3.10 or later. The script only uses the standard library: there is nothing
  to install to run it or to run the tests.
- Optional:
  - [ruff](https://docs.astral.sh/ruff/) for formatting and linting.
  - [Node.js](https://nodejs.org/), only to check CVSS scores against the official
    FIRST calculators (see [CVSS scoring](#cvss-scoring)).

## Setup

```
git clone https://github.com/imncls/sbom-triage.git
cd sbom-triage
python -m venv .venv          # optional, only needed for development tools
.venv/Scripts/activate        # Windows; on Linux/macOS: source .venv/bin/activate
python -m pip install ruff    # optional
```

## Running from source

```
python sbom_triage.py --help
python sbom_triage.py example.cdx.json
python sbom_triage.py --input-dir <dir> --output-dir <dir>
```

`example.cdx.json` is a small synthetic SBOM with known vulnerabilities (log4j,
lodash, requests) and a few components the script must skip.

Progress and warnings go to stderr; the table and the JSON go to stdout or to the
files you choose. The OSV details cache is created in `.cache/` (or `--cache-dir`)
and can be deleted at any time.

The script calls the real services (OSV, CISA KEV, FIRST EPSS), so running it needs
network access. The tests do not.

## Project structure

```
sbom_triage.py            the whole tool, in sections:
                            purl and SBOM        reading SBOMs, purls, directory mode
                            HTTP and cache       HttpClient (retries, User-Agent), DiskCache
                            OSV                  querybatch, vulnerability details
                            CVSS v3.x and v2     FIRST equations
                            CVSS v4.0            port of the FIRST reference calculator
                            OSV data extraction  CVEs, fixed versions, malware, severity
                            KEV and EPSS
                            Findings and priority  grouping of duplicates, priority rules
                            Analysis             one round of queries for all SBOMs
                            Output               table and JSON reports
                            CLI                  arguments, exit codes
tests/test_sbom_triage.py unit and end-to-end tests (no network)
example.cdx.json          sample SBOM with vulnerabilities
pyproject.toml            settings for development tools (ruff); there is no build
README.md                 documentation for users
CONTRIBUTING.md           this guide
SECURITY.md               how to report vulnerabilities in the tool
AGENTS.md                 project rules
LICENSE                   MIT, plus the notice for the CVSS v4.0 port (BSD-2-Clause)
```

The tool is a single file on purpose, so it can be copied and run anywhere with just
Python.

## Rules in short

- Everything is written in English: code, comments, program output, tests, and
  documentation.
- Standard library only. Do not add runtime dependencies.
- Treat every input as untrusted: SBOMs, any file in an input directory, the cache,
  and every API response. Validate IDs before using them, strip control and
  invisible characters (`clean`) before printing external text, never use an ID as a
  file name, and only follow redirects to HTTPS.
- The tool only generates results. It does not store them or compare runs.
- If a data source fails, fail with a clear message; never fall back to stored data.
  In directory mode, a file that may be a CycloneDX SBOM but cannot be analyzed is an
  error (exit code 4), not a skipped file.
- Scoring code must cite its source (see [CVSS scoring](#cvss-scoring)).

## Before opening a pull request

```
python -m unittest
python -m ruff format .
python -m ruff check .
```

ruff reads its settings (line length 120, Python 3.10) from `pyproject.toml`.

- Add or update tests for any change in behavior, and a regression test for every
  bug fix.
- Keep README.md accurate.
- Do not commit `.cache/`, JSON reports, or SBOMs from real systems: they may reveal
  what a system runs.
- Report security problems in the tool privately, as described in
  [SECURITY.md](SECURITY.md), not in a public issue or pull request.

## Tests

```
python -m unittest
python -m unittest tests.test_sbom_triage.CvssTests   # a single test class
```

Tests must not use the network. Network code is tested by injecting:

- a fake `opener` into `HttpClient` (retries, backoff, headers), or
- a `FakeClient` (in the test file) that answers by URL prefix and records the
  requests, for OSV, KEV, EPSS, and end-to-end runs.

SBOMs and API responses are small and built inside the tests (see `cyclonedx()` and
`log4j_client()` in the test file).

## CVSS scoring

OSV only provides CVSS vectors, so the script computes the scores.

- **v2 and v3.x** use the equations and metric weights from the FIRST
  specifications. Each table and function cites the section it comes from.
- **v4.0** has no closed formula. The CVSS v4.0 section is a port of the FIRST
  reference calculator,
  [FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator)
  (BSD-2-Clause). Keep its copyright notice and license text in the code, keep the
  tables identical to the upstream files, and keep the steps and the order of
  operations, so results match the reference exactly.

If you change the scoring code, or update the v4.0 tables from a newer upstream
commit, check it against the official JavaScript calculators with Node.js:

1. Get the calculators:
   - v4.0: clone `https://github.com/FIRSTdotorg/cvss-v4-calculator` and use
     `metrics.js`, `cvss_lookup.js`, `max_composed.js`, `max_severity.js`, and
     `cvss_score.js`.
   - v3.1 and v3.0: `https://www.first.org/cvss/calculator/cvsscalc31.js` and
     `cvsscalc30.js` (`CVSS31.calculateCVSSFromVector` and
     `CVSS.calculateCVSSFromVector`).
2. Load the files with Node's `vm.runInThisContext` (they define globals) and score
   a list of vectors. For v4.0, build the selection as the calculator does: every
   metric of `expectedMetricOrder` set to `"X"`, then the values from the vector,
   and call `cvss_score(selected, cvssLookup_global, maxSeverity, macroVector(selected))`.
3. Score the same vectors with `sbom_triage.cvss_base_score` and compare. For v4.0,
   cover every Base metric combination (104,976 vectors) plus random vectors with
   Threat, Environmental, and Supplemental metrics. There must be no differences.
4. Add a few of the reference results to `CvssTests` in the test file.

Update the commit hash in the code and in the README if the tables change.

## Validating with real SBOMs

Public collections of real SBOMs are useful to check the tool after significant
changes:

- [CycloneDX/bom-examples](https://github.com/CycloneDX/bom-examples), folder
  `SBOM/` (CC0): CycloneDX JSON and XML in several spec versions.
- [chainguard-dev/bom-shelter](https://github.com/chainguard-dev/bom-shelter), folder
  `in-the-wild/`: CycloneDX and SPDX SBOMs from open source projects. On Windows,
  git cannot check out this repository because other folders contain file names
  with `:`; download only `in-the-wild/` (for example through the GitHub API and
  `raw.githubusercontent.com`).

Treat downloaded SBOMs as untrusted data: keep them in their own directory, outside
the repository.

Copy all files into one flat directory (the script does not read subdirectories)
and run:

```
python sbom_triage.py --input-dir <flat dir> --output-dir <reports dir>
```

Then check that:

- there are no tracebacks or unexpected errors;
- every skipped file is really not a CycloneDX JSON SBOM;
- the same SBOM in different spec versions (bom-examples has several) gives the same
  findings;
- the findings match the sources. For each package, the IDs in `id` and
  `related_ids` must be exactly what `POST https://api.osv.dev/v1/query` returns for
  its purl; KEV and EPSS values must match the KEV catalog and the EPSS API; scores
  must match the FIRST calculators; and the priority must follow the rules in the
  README. Run the check right after the script, so both use the same data.

## Data source assumptions

Some constants mirror external data and may need updating:

- `OSV_PURL_TYPES` and `OSV_DISTRO_NAMESPACES`: the purl types OSV maps to an
  ecosystem, from `osv/purl_helpers.py` in
  [google/osv.dev](https://github.com/google/osv.dev). Update them when OSV adds
  ecosystems, and update the list in the README.
- `MALICIOUS_CWE` and `MALICIOUS_ID_PREFIX`: how GHSA and OSV mark malware.
- The URLs of OSV, CISA KEV, and FIRST EPSS. Do not add new network destinations
  without discussing it first.

## Versioning

The version is `__version__` in `sbom_triage.py`; it also goes into the User-Agent
and into the `tool` field of the JSON reports. Use
[semantic versioning](https://semver.org/): a change in the JSON format, the priority
names, the `--fail-on` values, or the exit codes breaks the systems that consume the
output and needs a new major version.

`FORMAT_VERSION` is the version of the JSON report format, written as
`format_version` in every report so consumers can check it. Increase it on any
incompatible change to the reports (a removed or renamed field, a changed meaning or
type); adding a new field does not require it.

There is no build step: the tool is distributed as the single file
`sbom_triage.py`, which already includes the license notice of the CVSS v4.0 port.

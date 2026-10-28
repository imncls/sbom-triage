# sbom-triage

Reads CycloneDX JSON SBOMs, looks up known vulnerabilities in their components in
[OSV](https://osv.dev), and prioritizes them with the
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and
[EPSS](https://www.first.org/epss/). Only needs Python 3.10+ (standard library).

It is meant to support other tools: it reads a single SBOM or every SBOM in a
directory, and writes the results as JSON for another system to consume.

## Usage

```
python sbom_triage.py sbom.cdx.json                          # table in the console
python sbom_triage.py sbom.cdx.json --json findings.json     # also export to JSON
python sbom_triage.py sbom.cdx.json --json -                 # JSON only, to stdout
python sbom_triage.py --input-dir sboms/ --output-dir out/   # every SBOM in a directory
python sbom_triage.py sbom.cdx.json --fail-on high           # exit code 3 if anything is HIGH or CRITICAL
python sbom_triage.py sbom.cdx.json --cache-dir /tmp/vw      # different cache directory
```

Sample output:

```
PRIORITY  PACKAGE@VERSION                           ID                      CVE             CVSS  EPSS        KEV                        FIXED IN
--------  ----------------------------------------  ----------------------  --------------  ----  ----------  -------------------------  --------
CRITICAL  ...pache.logging.log4j/log4j-core@2.14.1  GHSA-jfh8-c2jp-5v3q     CVE-2021-44228  10.0  1.000 p100  YES 2021-12-10 ransomware  2.15.0
HIGH      lodash@4.17.15                            GHSA-35jh-r3h4-6jhm     CVE-2021-23337  7.2   0.213 p98   no                         4.17.21
MEDIUM    requests@2.19.0                           GHSA-x84v-xcm2-53pg +1  CVE-2018-18074  7.5   0.069 p94   no                         2.20.0
```

Warnings (components without a purl or version, skipped files, retries) go to stderr.

**FIXED IN** shows the lowest fixed version that is not older than the installed
one: for log4j 2.14.1 it shows `2.15.0`, not the fixes for other branches (`2.3.1`,
`2.12.2`). Only the numeric part of the version is compared; if any version does
not start with a digit, all of them are shown. In JSON, `fixed_versions` has all of
them and `upgrade_to` the chosen one.

### Examples

Check one SBOM and see the findings in the console:

```
python sbom_triage.py app.cdx.json
```

Analyze every SBOM that another process drops into a directory, and write one JSON
report per SBOM for the system that consumes them:

```
python sbom_triage.py --input-dir /data/sboms --output-dir /data/vuln-reports
```

With `sboms/app.cdx.json` and `sboms/api.json`, this writes
`vuln-reports/app.cdx.triage.json` and `vuln-reports/api.triage.json`. Files in
`sboms/` that are not CycloneDX JSON SBOMs are skipped with a warning.

Fail a CI job when there is anything HIGH or CRITICAL (exit code 3), keeping the
report as a build artifact:

```
python sbom_triage.py sbom.cdx.json --json vuln-report.json --fail-on high
```

The same check in a shell script, telling findings apart from errors:

```sh
python sbom_triage.py --input-dir sboms --output-dir reports --fail-on critical
case $? in
  0) echo "no CRITICAL findings" ;;
  3) echo "CRITICAL findings: see reports/" ; exit 1 ;;
  *) echo "the analysis failed" ; exit 2 ;;
esac
```

And in PowerShell:

```powershell
python sbom_triage.py --input-dir sboms --output-dir reports --fail-on critical
switch ($LASTEXITCODE) {
  0 { "no CRITICAL findings" }
  3 { "CRITICAL findings: see reports\"; exit 1 }
  default { "the analysis failed"; exit 2 }
}
```

Send the JSON to another tool through stdout, e.g. list the packages with
CRITICAL findings with [jq](https://jqlang.github.io/jq/):

```
python sbom_triage.py sbom.cdx.json --json - | jq -r '.findings[] | select(.priority == "CRITICAL") | .package'
```

Use a fixed cache directory when the script runs from different working
directories (e.g. a scheduled task):

```
python /opt/sbom-triage/sbom_triage.py --input-dir /data/sboms --output-dir /data/vuln-reports --cache-dir /var/cache/sbom-triage
```

### Reading a directory

`--input-dir DIR` analyzes every file directly inside `DIR` (subdirectories are not
read and symlinks are not followed). Each file is identified by its content (see
[Supported input formats](#supported-input-formats)):

- Files that are not CycloneDX JSON SBOMs are skipped with a warning. Only the first
  few KB of a file are read to rule out non-JSON content, so large unrelated files
  are not loaded.
- A file that may be a CycloneDX SBOM but cannot be analyzed is an **error**: it
  starts like one but is invalid (for example, it is still being written), it has an
  unsupported `specVersion`, it cannot be read, or it does not fit in memory. The
  other SBOMs are still analyzed and reported, and the script exits with code 4, so
  the system that consumes the reports knows that one is missing.

There is no size limit for SBOMs.

If another process writes the SBOMs into the directory, it should write each file
atomically: write it under a temporary name (or in another directory on the same
disk) and then rename it. Otherwise this script may read a file that is only half
written.

All SBOMs are looked up together: each package is queried once even if it appears
in several SBOMs.

`--output-dir DIR` writes one `<name>.triage.json` per SBOM (e.g. `app.cdx.json` →
`app.cdx.triage.json`). It works with a single SBOM too, and must be different from
`--input-dir`. `--json` is only for a single SBOM.

### Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Finished successfully (and, with `--fail-on`, threshold not reached) |
| 1    | Error: invalid SBOM (single file), data source unavailable, unreadable or unwritable file |
| 2    | Invalid arguments                                              |
| 3    | `--fail-on`: there are findings with that priority or higher in any SBOM |
| 4    | Directory mode: a CycloneDX SBOM could not be analyzed (see above). Takes precedence over 3 |

`--fail-on` values: `critical`, `high`, `medium`, `no-data`, `low`.

### Integration with other systems

The script does not store results between runs: each run analyzes the whole input
and returns every finding. Storing them, comparing them with previous runs, or
alerting on new ones is up to the system that consumes the output. Each JSON report
has:

| Field | Content |
|-------|---------|
| `format_version` | Version of the report format (currently `1`). It changes only on incompatible changes; new fields may be added without changing it. |
| `tool` | `name`, `version`, and `url` of the tool that produced the report. |
| `generated_at` | Time of the analysis, in UTC (ISO 8601). |
| `sbom` | File name of the SBOM. |
| `coverage` | `analyzed_packages`, `skipped_components`, and `uncovered_purls`. |
| `findings` | One entry per vulnerability: `priority`, `package`, `purl`, `id`, `related_ids`, `malicious`, `summary`, `cves`, `cvss` (`score`, `vectors`, `label`), `epss` (`score`, `percentile`), `kev` (`in_kev`, `date_added`, `known_ransomware_campaign_use`), `fixed_versions`, and `upgrade_to`. |

- Each finding is identified by `purl` and `id`. The `id` is always chosen the same
  way (GHSA is preferred), and the other identifiers of the same vulnerability are
  in `related_ids`.
- `coverage` shows which part of the SBOM could be analyzed.

## Supported input formats

| Input | Supported |
|-------|-----------|
| CycloneDX JSON, `specVersion` 1.x | Yes. Tested with real SBOMs in 1.2, 1.3, 1.4, and 1.5. |
| CycloneDX JSON with a UTF-8 BOM | Yes |
| CycloneDX XML | No (skipped) |
| CycloneDX Protocol Buffers | No (skipped) |
| SPDX (JSON, tag-value, RDF, YAML) | No (skipped) |
| Any other file | No (skipped) |

A file is recognized by its content, not by its name or extension: it must be a JSON
object with `"bomFormat": "CycloneDX"` and a `specVersion` of the form `1.x`. A file
whose first bytes contain `"bomFormat": "CycloneDX"` (where CycloneDX tools write it)
but that is not a valid SBOM is treated as a broken SBOM, not as an unrelated file.

Inside the SBOM, the script reads `components`, including nested ones. Each
component needs a [purl](https://github.com/package-url/purl-spec) with a version
(`pkg:npm/lodash@4.17.15`); if the purl has no version, the component's `version`
field is used. Components without a purl or version are reported as not analyzed.

The purl types that OSV can look up are those of its ecosystems: `npm`, `pypi`,
`maven`, `gradle`, `golang`, `cargo`, `nuget`, `gem`, `composer`, `pub`, `hex`,
`swift`, `hackage`, `cran`, `conan`, `opam`, `julia`, `bitnami`, `dhi`, and the Linux
distributions `deb` (`debian`, `ubuntu`, `echo`), `rpm` (`redhat`, `almalinux`,
`rocky-linux`, `suse`, `opensuse`, `openeuler`, `mageia`, `azure-linux`), and `apk`
(`alpine`, `wolfi`, `chainguard`, `alpaquita`, `minimos`,
`bellsoft-hardened-containers`). Packages with other purl types are queried anyway,
and reported as not covered if OSV returns nothing for them.

## Priority

| Priority           | Rule                                                           |
|--------------------|----------------------------------------------------------------|
| CRITICAL           | Malicious package (`MAL-*` ID or CWE-506), or the CVE is in CISA KEV |
| HIGH               | EPSS percentile ≥ 0.95 or CVSS ≥ 9                             |
| MEDIUM             | CVSS ≥ 7                                                       |
| NO EPSS/KEV DATA   | The vulnerability has no CVE and its CVSS does not raise it to HIGH/MEDIUM |
| LOW                | Everything else                                                |

- The CVSS score is computed from the vector (v2, v3.0, v3.1, and v4.0; see
  [Scoring sources](#scoring-sources)). When there are several, the highest is used.
  If no vector can be scored, the database's qualitative severity is used (e.g.
  GHSA `HIGH`), shown in parentheses.
- A vulnerability without a CVE shows `n/a` for EPSS and KEV.
- Malicious packages are marked `CRITICAL malware` and listed first.
- OSV records that are the same vulnerability in a package (they reference each
  other as aliases or share a CVE, e.g. a GHSA and its PYSEC) are merged into one
  row with the highest severity of all of them. All malware advisories for the same
  package are also merged into one row. The ID column shows the main ID and `+N`
  for the rest; in JSON they are all in `related_ids`.

## Scoring sources

OSV only provides the CVSS **vector** (`severity[].score`, e.g.
`CVSS:3.1/AV:N/AC:L/...`), not the numeric score, so the script computes it. None
of the formulas or tables are invented; they come from FIRST, which maintains CVSS:

- **CVSS v3.0 / v3.1**: equations from section 7 of the
  [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document#7-Base-Metrics-Equations),
  metric weights from section 7.4, and the `Roundup` function from Appendix A.
  v3.0 uses the same equations and weights.
- **CVSS v2**: base equation and metric weights from section 3.2 of the
  [CVSS v2 guide](https://www.first.org/cvss/v2/guide#3-2-1-Base-Equation).
- **CVSS v4.0**: there is no closed formula; the score comes from a table of
  MacroVector scores and an interpolation algorithm
  ([specification, section 8](https://www.first.org/cvss/v4.0/specification-document#CVSS-v4-0-Scoring)).
  The script contains a Python port of the official FIRST calculator
  ([FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator),
  commit `c5b0d409`): the tables are copied unchanged and the algorithm keeps the
  same steps. It was checked against the reference JavaScript on all 104,976 Base
  metric combinations and on 20,000 random vectors with Threat, Environmental, and
  Supplemental metrics, with no differences.

The CVSS v4.0 calculator is © 2023 FIRST.ORG, Inc., Red Hat, and contributors,
distributed under the BSD-2-Clause license. Its copyright notice and license text
are reproduced in `sbom_triage.py`, at the start of the CVSS v4.0 section.

## Coverage

Each report shows how many packages were analyzed and what was left out: components
without a purl or version, and packages whose purl type OSV does not recognize. For
the latter OSV answers "no vulnerabilities" instead of returning an error, so the
script warns that they could not be analyzed. In JSON this is in `coverage`.

## How it works

1. Walks `components` (including nested ones). If the purl has no version, the
   component's `version` field is used; if there is none either, it warns and skips
   the component.
2. Queries `POST https://api.osv.dev/v1/querybatch` in batches of 1000 and follows
   `next_page_token`.
3. Fetches the details of each ID from `https://api.osv.dev/v1/vulns/{id}`.
4. Downloads the KEV catalog.
5. Queries EPSS at `https://api.first.org/data/v1/epss` in batches of 100 CVEs.

The OSV search, KEV, and EPSS are queried on every run, so a newly published
vulnerability or a CVE just added to KEV shows up on the next run.

The only cache is the OSV vulnerability details (step 3), stored in `.cache/osv/`
(file names are a hash of the ID). A cached entry is only reused while the OSV search
reports the same `modified` date for it, so it is never stale; it saves many requests
when analyzing many SBOMs.

All requests carry a User-Agent that identifies the tool and links to this
repository, and are retried with exponential backoff (honoring `Retry-After`) on
HTTP 429, 5xx, and network errors. Redirects are only followed to HTTPS URLs. If a
source still fails after the retries, the script exits with code 1 instead of
returning incomplete results. The one exception is an OSV record that no longer
exists when its details are requested (HTTP 404, e.g. withdrawn in the meantime): it
is left out with a warning, since there is nothing to report.

## Data sources and terms

The reports are built from third-party data. Each source has its own terms; check
them if you publish or redistribute the reports:

- **[OSV](https://osv.dev)** aggregates many vulnerability databases, each under its
  own license (for example CC-BY 4.0 for the GitHub Advisory Database, CC-BY-SA 4.0
  for Ubuntu, CC-BY-NC-ND 4.0 for Chainguard / Wolfi). The list is in
  [OSV's data sources](https://google.github.io/osv.dev/data/). Reports include data
  from these records (summaries, aliases, severity, fixed versions).
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** is
  released under CC0 ([license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)).
- **[EPSS](https://www.first.org/epss/)** scores are published freely by FIRST and the
  EPSS SIG; see [FIRST's terms of use](https://www.first.org/about/policies/terms).

## Security

To report a vulnerability in sbom-triage itself, see [SECURITY.md](SECURITY.md).
Please do not open a public issue.

## Tests

```
python -m unittest
```

The tests do not use the network.

## Contributing

The code is open: fork it and change it as you like ([MIT License](LICENSE)). To set up a
development environment, run the script and its tests from source, check the CVSS
scores against the official FIRST calculators, or validate the results with public
SBOM collections, see [CONTRIBUTING.md](CONTRIBUTING.md).

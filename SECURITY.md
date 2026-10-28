# Security policy

sbom-triage is a security tool, so vulnerabilities in it are taken seriously.

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through
GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/imncls/sbom-triage/security/advisories/new).

Include, if possible:

- the version (`python sbom_triage.py --version`) and the Python version;
- what an attacker can do and under which conditions;
- steps or a minimal input (SBOM, API response) that reproduce it. Do not include
  SBOMs or reports from real systems.

You will get an answer as soon as possible. Once the problem is confirmed, a fix is
prepared and released, and the report is published as a GitHub security advisory,
crediting you unless you prefer otherwise.

## Scope

In scope, for example:

- a crafted SBOM, file in an input directory, or API response that makes the tool
  crash, hang, read or write files outside the chosen paths, or run code;
- output that a crafted input can falsify or hide (for example terminal escape
  sequences, or a finding reported with the wrong priority);
- requests sent anywhere other than the documented data sources.

Out of scope:

- wrong or missing data in OSV, CISA KEV, or FIRST EPSS: report those to the source;
- vulnerabilities in the packages listed in your SBOMs: that is what the tool reports.

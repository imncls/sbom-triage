#!/usr/bin/env python3
"""Looks up known vulnerabilities in the components of CycloneDX JSON SBOMs.

Queries OSV by purl, enriches each vulnerability with CISA KEV and EPSS, and
assigns it a priority. Reads a single SBOM or every SBOM in a directory. Uses
only the Python 3 standard library.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import itertools
import json
import logging
import math
import os
import random
import re
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__version__ = "1.0.0"
TOOL_NAME = "sbom-triage"
PROJECT_URL = "https://github.com/imncls/sbom-triage"
# Version of the JSON report format. Increase it on any incompatible change.
FORMAT_VERSION = 1

USER_AGENT = f"{TOOL_NAME}/{__version__} (+{PROJECT_URL})"

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

OSV_BATCH_SIZE = 1000
OSV_MAX_PAGE_ROUNDS = 50
EPSS_BATCH_SIZE = 100
DETAIL_WORKERS = 8

HTTP_TIMEOUT_SECONDS = 30
HTTP_MAX_ATTEMPTS = 5
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 60.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

# Only the start of a file is read to decide whether it can be a JSON SBOM, so large
# files that are not (binaries, XML) are skipped without loading them.
SNIFF_BYTES = 4096
UTF8_BOM = b"\xef\xbb\xbf"
SPEC_VERSION_RE = re.compile(r"^1\.\d+$")
# CycloneDX tools write bomFormat at the start of the document, so a file whose first
# bytes contain it is a CycloneDX SBOM even if it cannot be parsed (e.g. half written).
CYCLONEDX_MARKER_RE = re.compile(rb'"bomFormat"\s*:\s*"CycloneDX"')
OUTPUT_SUFFIX = ".triage.json"

# IDs come from an external API. Some contain ":" (e.g. openSUSE-SU-2024:0001-1);
# they are never used as file names (see _cache_name).
VULN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Control characters, invisible format characters (including bidirectional overrides
# such as U+202E) and line/paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

# purl types that OSV maps to an ecosystem (osv.dev, osv/purl_helpers.py).
# For other types OSV answers "no vulnerabilities" instead of returning an error.
OSV_PURL_TYPES = frozenset(
    {
        "bitnami", "cargo", "composer", "conan", "cran", "dhi", "gem", "golang", "gradle",
        "hackage", "hex", "julia", "maven", "npm", "nuget", "opam", "pub", "pypi", "swift",
    }
)  # fmt: skip
# Distribution types are only recognized together with their namespace.
OSV_DISTRO_NAMESPACES = {
    "apk": frozenset({"alpaquita", "alpine", "bellsoft-hardened-containers", "chainguard", "minimos", "wolfi"}),
    "deb": frozenset({"debian", "echo", "ubuntu"}),
    "rpm": frozenset(
        {"almalinux", "azure-linux", "mageia", "openeuler", "opensuse", "redhat", "rocky-linux", "suse"}
    ),
}

# CWE-506 (Embedded Malicious Code) marks GHSA malware advisories; OSV uses MAL- IDs.
MALICIOUS_CWE = "CWE-506"
MALICIOUS_ID_PREFIX = "MAL-"

PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH = "HIGH"
PRIORITY_MEDIUM = "MEDIUM"
PRIORITY_NO_DATA = "NO EPSS/KEV DATA"
PRIORITY_LOW = "LOW"
# Without a CVE, active exploitation cannot be ruled out, so it ranks above LOW.
PRIORITY_ORDER = (
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    PRIORITY_MEDIUM,
    PRIORITY_NO_DATA,
    PRIORITY_LOW,
)

# --fail-on values: lowercase and without spaces, so they are easy to type.
FAIL_ON_CHOICES = {
    "critical": PRIORITY_CRITICAL,
    "high": PRIORITY_HIGH,
    "medium": PRIORITY_MEDIUM,
    "no-data": PRIORITY_NO_DATA,
    "low": PRIORITY_LOW,
}
EXIT_FAIL_ON = 3
EXIT_SBOM_FAILED = 4

logger = logging.getLogger("sbom_triage")


class SbomError(Exception):
    """An input cannot be read or analyzed."""


class NotAnSbomError(SbomError):
    """The file is readable but is not a CycloneDX JSON SBOM."""


class ApiError(Exception):
    """An external data source failed or returned something unexpected."""


class NotFoundError(ApiError):
    """The requested resource does not exist (HTTP 404)."""


def clean(text: Any) -> str:
    """Strips control and invisible formatting characters, so external data cannot
    tamper with the terminal or disguise what it shows (e.g. with bidirectional overrides)."""
    return "".join(char for char in str(text) if unicodedata.category(char) not in _UNSAFE_CATEGORIES)


# --- purl and SBOM -----------------------------------------------------------


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str


def parse_purl(purl: str) -> Purl:
    if not purl.startswith("pkg:"):
        raise ValueError("does not start with pkg:")
    remainder = purl[4:].lstrip("/").split("#", 1)[0].split("?", 1)[0]
    purl_type, _, path = remainder.partition("/")
    segments = [segment for segment in path.split("/") if segment]
    if not purl_type or not segments:
        raise ValueError("missing type or name")
    name, _, version = segments[-1].partition("@")
    namespace = "/".join(urllib.parse.unquote(s) for s in segments[:-1])
    name = urllib.parse.unquote(name)
    if not name:
        raise ValueError("missing name")
    return Purl(purl_type.lower(), namespace, name, urllib.parse.unquote(version))


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


@dataclass(frozen=True)
class PackageRef:
    """A package to query, already deduplicated."""

    purl: str
    parsed: Purl
    # Only when the purl has no version and it is taken from the component's version field.
    query_version: str | None

    @property
    def version(self) -> str:
        return self.query_version or self.parsed.version

    @property
    def label(self) -> str:
        name = self.parsed.name
        if self.parsed.namespace:
            name = f"{self.parsed.namespace}/{name}"
        return f"{name}@{self.version}"

    @property
    def key(self) -> str:
        return f"{self.purl}|{self.query_version or ''}"

    @property
    def osv_supported(self) -> bool:
        distros = OSV_DISTRO_NAMESPACES.get(self.parsed.type)
        if distros is not None:
            return self.parsed.namespace.lower() in distros
        return self.parsed.type in OSV_PURL_TYPES

    def matches(self, ecosystem_name: str) -> bool:
        ns, name = self.parsed.namespace, self.parsed.name
        candidates = {name, f"{ns}/{name}", f"{ns}:{name}"} if ns else {name}
        return _normalize_name(ecosystem_name) in {_normalize_name(c) for c in candidates}


def read_sbom(path: Path) -> dict[str, Any]:
    """Loads a file and checks from its content that it is a CycloneDX JSON SBOM.

    Raises NotAnSbomError for files that are not CycloneDX JSON, and SbomError for files
    that cannot be analyzed although they may be SBOMs: unreadable, too large for memory,
    or starting like a CycloneDX SBOM but invalid (e.g. still being written). There is no
    size limit.
    """
    name = clean(path.name)
    looks_like_cyclonedx = False
    try:
        with path.open("rb") as handle:
            head = handle.read(SNIFF_BYTES)
            looks_like_cyclonedx = CYCLONEDX_MARKER_RE.search(head) is not None
            if not head.removeprefix(UTF8_BOM).lstrip().startswith(b"{"):
                raise _invalid_sbom(looks_like_cyclonedx, f"{name} is not a JSON object")
            raw = head + handle.read()
        bom = json.loads(raw)
    except OSError as error:
        raise SbomError(f"{name} cannot be read") from error
    except MemoryError as error:
        raise SbomError(f"{name} is too large to load into memory") from error
    except (ValueError, RecursionError) as error:
        raise _invalid_sbom(looks_like_cyclonedx, f"{name} is not valid JSON") from error
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise NotAnSbomError(f"{name} is not a CycloneDX SBOM (bomFormat)")
    spec_version = bom.get("specVersion")
    if not isinstance(spec_version, str) or not SPEC_VERSION_RE.match(spec_version):
        raise SbomError(f"{name} has an unsupported CycloneDX specVersion: {clean(spec_version)}")
    return bom


def _invalid_sbom(looks_like_cyclonedx: bool, message: str) -> SbomError:
    return SbomError(message) if looks_like_cyclonedx else NotAnSbomError(message)


def sbom_candidates(directory: Path) -> list[Path]:
    """Regular files directly inside the directory, sorted. Symlinks are not followed,
    so nothing outside the directory is read."""
    try:
        entries = sorted(directory.iterdir())
    except OSError as error:
        raise SbomError(f"cannot list directory {directory}") from error
    return [entry for entry in entries if not entry.is_symlink() and entry.is_file()]


def iter_components(components: Any) -> Iterator[dict[str, Any]]:
    """Walks nested components without recursion (the SBOM is untrusted input)."""
    stack = _component_dicts(components)
    while stack:
        component = stack.pop()
        yield component
        stack.extend(_component_dicts(component.get("components")))


def _component_dicts(components: Any) -> list[dict[str, Any]]:
    """Components in reverse order, ready to push onto the stack."""
    if not isinstance(components, list):
        return []
    return [component for component in reversed(components) if isinstance(component, dict)]


@dataclass(frozen=True)
class SbomScan:
    source: str
    packages: list[PackageRef]
    # Components without a purl, with an invalid purl, or without a version: not analyzed.
    skipped_components: int


def extract_packages(bom: dict[str, Any], source: str) -> SbomScan:
    packages: dict[str, PackageRef] = {}
    skipped = 0
    source = clean(source)
    for component in iter_components(bom.get("components")):
        display = clean(component.get("name") or component.get("bom-ref") or "?")
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl.strip():
            logger.warning("%s: component without a purl: %s", source, display)
            skipped += 1
            continue
        purl = purl.strip()
        try:
            parsed = parse_purl(purl)
        except ValueError as error:
            logger.warning("%s: invalid purl in %s (%s): %s", source, display, error, clean(purl))
            skipped += 1
            continue
        query_version = None
        if not parsed.version:
            component_version = component.get("version")
            if not isinstance(component_version, str) or not component_version.strip():
                logger.warning("%s: component without a version, skipped: %s", source, clean(purl))
                skipped += 1
                continue
            query_version = component_version.strip()
        package = PackageRef(purl, parsed, query_version)
        packages.setdefault(package.key, package)
    return SbomScan(source, list(packages.values()), skipped)


@dataclass(frozen=True)
class Inputs:
    scans: list[SbomScan]
    # Files that are not CycloneDX JSON SBOMs.
    skipped_files: int = 0
    # Files that may be CycloneDX SBOMs but could not be analyzed.
    failed_files: tuple[str, ...] = ()


def load_directory(directory: Path) -> Inputs:
    """Scans every SBOM in the directory."""
    if not directory.is_dir():
        raise SbomError(f"{directory} is not a directory")
    scans: list[SbomScan] = []
    skipped = 0
    failed: list[str] = []
    for path in sbom_candidates(directory):
        try:
            scans.append(extract_packages(read_sbom(path), path.name))
        except NotAnSbomError as error:
            logger.warning("skipped: %s", error)
            skipped += 1
        except SbomError as error:
            logger.error("cannot analyze: %s", error)
            failed.append(clean(path.name))
    logger.info("%d CycloneDX SBOMs found, %d files skipped, %d failed", len(scans), skipped, len(failed))
    return Inputs(scans, skipped, tuple(failed))


# --- HTTP and cache ----------------------------------------------------------

Opener = Callable[[urllib.request.Request, float], Any]


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects only to HTTPS URLs, so a redirect cannot downgrade the connection."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ApiError(f"{_host(req.full_url)} redirected to a non-HTTPS URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@functools.cache
def _https_opener() -> urllib.request.OpenerDirector:
    """Built on first use, so importing the module does not set up TLS."""
    return urllib.request.build_opener(_HttpsOnlyRedirectHandler)


def _default_opener(request: urllib.request.Request, timeout: float) -> Any:
    return _https_opener().open(request, timeout=timeout)


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


class HttpClient:
    """JSON client with its own User-Agent and backoff retries on 429/5xx."""

    def __init__(
        self,
        opener: Opener = _default_opener,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = HTTP_MAX_ATTEMPTS,
        timeout: float = HTTP_TIMEOUT_SECONDS,
    ) -> None:
        self._opener = opener
        self._sleep = sleep
        self._max_attempts = max_attempts
        self._timeout = timeout

    def get_json(self, url: str) -> Any:
        return self._request(url, None)

    def post_json(self, url: str, payload: Any) -> Any:
        return self._request(url, json.dumps(payload).encode("utf-8"))

    def _request(self, url: str, body: bytes | None) -> Any:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        method = "GET" if body is None else "POST"
        for attempt in range(1, self._max_attempts + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with self._opener(request, self._timeout) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
            except urllib.error.HTTPError as error:
                retry_after = error.headers.get("Retry-After") if error.headers else None
                error.close()
                if error.code == 404:
                    raise NotFoundError(f"{_host(url)} returned HTTP 404") from error
                retryable = error.code == 429 or 500 <= error.code < 600
                if retryable and attempt < self._max_attempts:
                    self._backoff(attempt, retry_after, f"HTTP {error.code}", url)
                    continue
                raise ApiError(f"{_host(url)} returned HTTP {error.code}") from error
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                if attempt < self._max_attempts:
                    self._backoff(attempt, None, "network error", url)
                    continue
                raise ApiError(f"could not connect to {_host(url)}") from error
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ApiError(f"response from {_host(url)} is too large")
            try:
                return json.loads(raw)
            except (ValueError, RecursionError) as error:
                raise ApiError(f"invalid response from {_host(url)}") from error
        raise AssertionError("unreachable")

    def _backoff(self, attempt: int, retry_after: str | None, reason: str, url: str) -> None:
        delay = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))
        delay += random.uniform(0, BACKOFF_BASE_SECONDS)
        if retry_after and retry_after.strip().isdigit():
            delay = max(delay, min(float(retry_after.strip()), BACKOFF_MAX_SECONDS))
        logger.info("%s from %s, retrying in %.1f s", reason, _host(url), delay)
        self._sleep(delay)


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


class DiskCache:
    """Stores OSV vulnerability details. Entries are only reused while OSV reports the
    same modified date, so they are never stale."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def read_json(self, relative: str) -> Any | None:
        try:
            return json.loads((self.root / relative).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, RecursionError):
            logger.warning("unreadable cache entry, discarded: %s", relative)
            return None

    def write_json(self, relative: str, data: Any) -> None:
        write_json_atomic(self.root / relative, data)


# --- OSV ---------------------------------------------------------------------


def _osv_query(package: PackageRef, page_token: str | None) -> dict[str, Any]:
    query: dict[str, Any] = {"package": {"purl": package.purl}}
    if package.query_version:
        query["version"] = package.query_version
    if page_token:
        query["page_token"] = page_token
    return query


def query_osv(client: HttpClient, packages: list[PackageRef]) -> dict[PackageRef, dict[str, str]]:
    """Returns, per package, {vulnerability id: modified date}."""
    found: dict[PackageRef, dict[str, str]] = {package: {} for package in packages}
    pending: list[tuple[PackageRef, str | None]] = [(package, None) for package in packages]
    for _ in range(OSV_MAX_PAGE_ROUNDS):
        if not pending:
            return found
        next_pending: list[tuple[PackageRef, str | None]] = []
        for start in range(0, len(pending), OSV_BATCH_SIZE):
            chunk = pending[start : start + OSV_BATCH_SIZE]
            response = client.post_json(
                OSV_QUERYBATCH_URL, {"queries": [_osv_query(p, token) for p, token in chunk]}
            )
            results = response.get("results") if isinstance(response, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                raise ApiError("unexpected response from OSV querybatch")
            for (package, _), result in zip(chunk, results):
                if not isinstance(result, dict):
                    continue
                for vuln in result.get("vulns") or []:
                    vuln_id = vuln.get("id") if isinstance(vuln, dict) else None
                    if not isinstance(vuln_id, str) or not VULN_ID_RE.match(vuln_id):
                        logger.warning("invalid vulnerability ID from OSV: %s", clean(vuln_id))
                        continue
                    found[package][vuln_id] = str(vuln.get("modified") or "")
                token = result.get("next_page_token")
                if isinstance(token, str) and token:
                    next_pending.append((package, token))
        pending = next_pending
    if pending:
        logger.warning("OSV still paginating after %d rounds; results are incomplete", OSV_MAX_PAGE_ROUNDS)
    return found


def fetch_vuln_details(
    client: HttpClient, cache: DiskCache, modified_by_id: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Fetches the details of each ID, reusing the cache if it has not changed in OSV.

    A record that no longer exists (HTTP 404, e.g. withdrawn between the search and this
    request) is left out with a warning: it is not missing data, there is nothing to report.
    """

    def load(vuln_id: str, modified: str) -> dict[str, Any] | None:
        relative = f"osv/{_cache_name(vuln_id)}.json"
        cached = cache.read_json(relative)
        # Without a modified date there is no way to tell whether the copy is current.
        if (
            modified
            and isinstance(cached, dict)
            and cached.get("id") == vuln_id
            and cached.get("modified") == modified
        ):
            return cached
        try:
            data = client.get_json(OSV_VULN_URL.format(urllib.parse.quote(vuln_id, safe="")))
        except NotFoundError:
            logger.warning("OSV record %s no longer exists; skipped", vuln_id)
            return None
        if not isinstance(data, dict):
            raise ApiError(f"unexpected OSV details for {vuln_id}")
        cache.write_json(relative, data)
        return data

    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
        futures = {vid: pool.submit(load, vid, mod) for vid, mod in modified_by_id.items()}
    results = {vuln_id: future.result() for vuln_id, future in futures.items()}
    return {vuln_id: data for vuln_id, data in results.items() if data is not None}


def _cache_name(vuln_id: str) -> str:
    """Hash of the ID: valid on any file system, with no Windows reserved names
    (CON, NUL...) and no collisions on case-insensitive file systems."""
    return hashlib.sha256(vuln_id.encode("utf-8")).hexdigest()


# --- CVSS v3.x and v2 --------------------------------------------------------
# OSV only provides the CVSS vector (severity[].score), not the numeric score, so
# the base score is computed here with the official FIRST equations.
#
# CVSS v3.1 specification, section 7 (base metrics equations), metric weights in
# section 7.4 and Roundup in Appendix A:
# https://www.first.org/cvss/v3.1/specification-document#7-Base-Metrics-Equations
# CVSS v3.0 uses the same equations and weights.

_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# CVSS v2 guide, section 3.2.1 (base equation) and section 3.2.4 (metric weights):
# https://www.first.org/cvss/v2/guide#3-2-1-Base-Equation
_CVSS2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_CVSS2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_CVSS2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_CVSS2_CIA = {"N": 0.0, "P": 0.275, "C": 0.66}


def _vector_metrics(parts: Iterable[str]) -> dict[str, str]:
    return dict(part.split(":", 1) for part in parts if ":" in part)


def _roundup(value: float) -> float:
    """Roundup from the CVSS 3.1 specification, Appendix A (avoids floating-point errors)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.x base score (specification section 7.1):

    ISS = 1 - (1 - C) * (1 - I) * (1 - A)
    Impact = 6.42 * ISS (scope unchanged)
           = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15 (scope changed)
    Exploitability = 8.22 * AV * AC * PR * UI
    Base = Roundup(min(Impact + Exploitability, 10)), or
           Roundup(min(1.08 * (Impact + Exploitability), 10)) if the scope changed;
           0 if Impact <= 0.
    """
    parts = vector.strip().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = _vector_metrics(parts[1:])
    try:
        scope = metrics["S"]
        if scope not in ("U", "C"):
            return None
        changed = scope == "C"
        privileges = (_CVSS3_PR_CHANGED if changed else _CVSS3_PR_UNCHANGED)[metrics["PR"]]
        exploitability = (
            8.22 * _CVSS3_AV[metrics["AV"]] * _CVSS3_AC[metrics["AC"]] * privileges * _CVSS3_UI[metrics["UI"]]
        )
        c, i, a = (_CVSS3_CIA[metrics[key]] for key in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def cvss2_base_score(vector: str) -> float | None:
    """CVSS v2 base score (guide section 3.2.1):

    Impact = 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))
    Exploitability = 20 * AV * AC * Au
    f(Impact) = 0 if Impact == 0 else 1.176
    Base = round_to_1_decimal(((0.6 * Impact) + (0.4 * Exploitability) - 1.5) * f(Impact))
    """
    text = vector.strip().strip("()")
    if text.startswith("CVSS:2.0/"):
        text = text[len("CVSS:2.0/") :]
    metrics = _vector_metrics(text.split("/"))
    try:
        c, i, a = (_CVSS2_CIA[metrics[key]] for key in ("C", "I", "A"))
        exploitability = 20 * _CVSS2_AV[metrics["AV"]] * _CVSS2_AC[metrics["AC"]] * _CVSS2_AU[metrics["Au"]]
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    factor = 0 if impact == 0 else 1.176
    return math.floor(((0.6 * impact + 0.4 * exploitability - 1.5) * factor) * 10 + 0.5) / 10


# --- CVSS v4.0 ---------------------------------------------------------------
# CVSS v4.0 has no closed formula: the score comes from a table of MacroVector scores
# and an interpolation algorithm (specification section 8,
# https://www.first.org/cvss/v4.0/specification-document#CVSS-v4-0-Scoring).
#
# This section is a Python port of the FIRST reference implementation, the official
# CVSS v4.0 calculator: https://github.com/FIRSTdotorg/cvss-v4-calculator
# (commit c5b0d409ae9f57c44264c6ce5f27d89298e1d32a), files cvss_score.js,
# cvss_lookup.js, max_composed.js, max_severity.js and metrics.js. The tables are
# copied unchanged and the algorithm keeps the same steps and order of operations,
# so the results match the reference calculator. Its license:
#
# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Metric order and valid values (metrics.js). The first 11 are the mandatory Base metrics.
_CVSS4_VALUES: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U"),
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
_CVSS4_ORDER = tuple(_CVSS4_VALUES)
_CVSS4_BASE_COUNT = 11

# Score of each MacroVector (cvss_lookup.js).
_CVSS4_LOOKUP = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8.0, "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5.0,
    "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0,
    "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
    "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1,
    "011211": 5.2, "011220": 5.0, "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7.0, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9.0, "110010": 8.8,
    "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
    "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0,
    "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3, "210101": 5.5, "210110": 5.9,
    "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
    "211011": 4.5, "211020": 4.0, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
    "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
}  # fmt: skip

# Highest severity vectors of each MacroVector level (max_composed.js).
_CVSS4_MAX_COMPOSED: dict[str, Any] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

# Maximal severity distances inside each MacroVector level, +1 (max_severity.js).
_CVSS4_MAX_SEVERITY: dict[str, Any] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
}

# Index of each metric value, used for the severity distance (cvss_score.js).
_CVSS4_LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}


def _parse_cvss4(vector: str) -> dict[str, str] | None:
    """Metric values of a CVSS v4.0 vector, with "X" for the metrics not present.

    Same validation as setButtonsToVector in app.js: metrics in the specification
    order, all Base metrics present, and only valid values.
    """
    parts = vector.strip().split("/")
    if parts[0] != "CVSS:4.0":
        return None
    selected = {name: "X" for name in _CVSS4_ORDER}
    position = 0
    for part in parts[1:]:
        name, separator, value = part.partition(":")
        while position < len(_CVSS4_ORDER) and _CVSS4_ORDER[position] != name:
            if position < _CVSS4_BASE_COUNT:
                return None
            position += 1
        if not separator or position == len(_CVSS4_ORDER) or value not in _CVSS4_VALUES[name]:
            return None
        selected[name] = value
        position += 1
    if position < _CVSS4_BASE_COUNT:
        return None
    return selected


def _cvss4_value(selected: dict[str, str], metric: str) -> str:
    """Effective value of a metric (function m in cvss_score.js)."""
    value = selected[metric]
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = selected.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def _cvss4_macro_vector(selected: dict[str, str]) -> str:
    """MacroVector of the six equivalence classes (function macroVector in cvss_score.js)."""

    def v(metric: str) -> str:
        return _cvss4_value(selected, metric)

    if v("AV") == "N" and v("PR") == "N" and v("UI") == "N":
        eq1 = 0
    elif (v("AV") == "N" or v("PR") == "N" or v("UI") == "N") and v("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if v("AC") == "L" and v("AT") == "N" else 1
    if v("VC") == "H" and v("VI") == "H":
        eq3 = 0
    elif v("VC") == "H" or v("VI") == "H" or v("VA") == "H":
        eq3 = 1
    else:
        eq3 = 2
    if v("MSI") == "S" or v("MSA") == "S":
        eq4 = 0
    elif v("SC") == "H" or v("SI") == "H" or v("SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[v("E")]
    if (
        (v("CR") == "H" and v("VC") == "H")
        or (v("IR") == "H" and v("VI") == "H")
        or (v("AR") == "H" and v("VA") == "H")
    ):
        eq6 = 0
    else:
        eq6 = 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _cvss4_lookup(eq1: int, eq2: int, eq3: int, eq4: int, eq5: int, eq6: int) -> float | None:
    return _CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}")


def _js_round(value: float) -> float:
    """Math.round(value * 10) / 10 as in JavaScript: halves are rounded up."""
    scaled = value * 10
    whole = math.floor(scaled)
    return (whole + 1 if scaled - whole >= 0.5 else whole) / 10


def cvss4_score(vector: str) -> float | None:
    """CVSS v4.0 score (function cvss_score in cvss_score.js)."""
    selected = _parse_cvss4(vector)
    if selected is None:
        return None

    def v(metric: str) -> str:
        return _cvss4_value(selected, metric)

    if all(v(metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _cvss4_macro_vector(selected)
    value = _CVSS4_LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(digit) for digit in macro)

    # 1.a Maximal scoring difference with the next lower MacroVector of each EQ.
    lower_eq1 = _cvss4_lookup(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    lower_eq2 = _cvss4_lookup(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 1 and eq6 == 1:
        lower_eq3eq6 = _cvss4_lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 0 and eq6 == 1:
        lower_eq3eq6 = _cvss4_lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        lower_eq3eq6 = _cvss4_lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:
        left = _cvss4_lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = _cvss4_lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        # In JavaScript a comparison with a missing score is false, so "right" wins.
        lower_eq3eq6 = left if left is not None and right is not None and left > right else right
    else:
        lower_eq3eq6 = _cvss4_lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    lower_eq4 = _cvss4_lookup(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    lower_eq5 = _cvss4_lookup(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    # 1.b Severity distance from the first highest severity vector of the MacroVector
    # that is not below the scored vector.
    max_vectors = itertools.product(
        _CVSS4_MAX_COMPOSED["eq1"][eq1],
        _CVSS4_MAX_COMPOSED["eq2"][eq2],
        _CVSS4_MAX_COMPOSED["eq3"][eq3][str(eq6)],
        _CVSS4_MAX_COMPOSED["eq4"][eq4],
        _CVSS4_MAX_COMPOSED["eq5"][eq5],
    )
    distance: dict[str, float] = {}
    for parts in max_vectors:
        max_vector = _vector_metrics("".join(parts).split("/"))
        distance = {
            metric: levels[v(metric)] - levels[max_vector[metric]] for metric, levels in _CVSS4_LEVELS.items()
        }
        if all(d >= 0 for d in distance.values()):
            break

    current_eq1 = distance["AV"] + distance["PR"] + distance["UI"]
    current_eq2 = distance["AC"] + distance["AT"]
    current_eq3eq6 = (
        distance["VC"] + distance["VI"] + distance["VA"] + distance["CR"] + distance["IR"] + distance["AR"]
    )
    current_eq4 = distance["SC"] + distance["SI"] + distance["SA"]

    step = 0.1
    max_severity_eq1 = _CVSS4_MAX_SEVERITY["eq1"][eq1] * step
    max_severity_eq2 = _CVSS4_MAX_SEVERITY["eq2"][eq2] * step
    max_severity_eq3eq6 = _CVSS4_MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_severity_eq4 = _CVSS4_MAX_SEVERITY["eq4"][eq4] * step

    # 1.c/1.d Proportion of the distance, applied to the maximal scoring difference.
    # A missing lower MacroVector (NaN in the reference) is ignored.
    existing_lower = 0
    normalized = []
    for lower, current, max_severity in (
        (lower_eq1, current_eq1, max_severity_eq1),
        (lower_eq2, current_eq2, max_severity_eq2),
        (lower_eq3eq6, current_eq3eq6, max_severity_eq3eq6),
        (lower_eq4, current_eq4, max_severity_eq4),
    ):
        if lower is None:
            normalized.append(0)
            continue
        existing_lower += 1
        normalized.append((value - lower) * (current / max_severity))
    if lower_eq5 is not None:
        # The proportion is always 0 for EQ5.
        existing_lower += 1
        normalized.append((value - lower_eq5) * 0)
    else:
        normalized.append(0)

    # 2. Mean of the proportional distances. 3. Subtract it from the MacroVector score.
    if existing_lower == 0:
        mean_distance = 0
    else:
        mean_distance = (normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4]) / existing_lower
    value -= mean_distance
    value = min(max(value, 0.0), 10.0)
    return _js_round(value)


def cvss_base_score(severity_type: str, vector: str) -> float | None:
    """Score from an OSV severity entry (CVSS_V2, CVSS_V3 or CVSS_V4)."""
    if severity_type == "CVSS_V4":
        return cvss4_score(vector)
    if severity_type == "CVSS_V3":
        return cvss3_base_score(vector)
    if severity_type == "CVSS_V2":
        return cvss2_base_score(vector)
    return None


# --- OSV data extraction -----------------------------------------------------


def _affected_for(data: dict[str, Any], package: PackageRef) -> list[dict[str, Any]]:
    """affected entries for the queried package; all of them if none clearly matches."""
    affected = [entry for entry in data.get("affected") or [] if isinstance(entry, dict)]
    matching = []
    for entry in affected:
        osv_package = entry.get("package")
        if not isinstance(osv_package, dict):
            continue
        osv_purl = osv_package.get("purl")
        if isinstance(osv_purl, str):
            try:
                parsed = parse_purl(osv_purl)
            except ValueError:
                parsed = None
            if parsed and parsed.type == package.parsed.type and package.matches(
                f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
            ):
                matching.append(entry)
                continue
        name = osv_package.get("name")
        if isinstance(name, str) and package.matches(name):
            matching.append(entry)
    return matching or affected


def fixed_versions(data: dict[str, Any], package: PackageRef) -> list[str]:
    versions: list[str] = []
    for entry in _affected_for(data, package):
        for version_range in entry.get("ranges") or []:
            if not isinstance(version_range, dict) or version_range.get("type") == "GIT":
                continue
            for event in version_range.get("events") or []:
                fixed = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(fixed, str) and clean(fixed) and clean(fixed) not in versions:
                    versions.append(clean(fixed))
    return versions


_NUMERIC_VERSION_RE = re.compile(r"^(?:(\d+):)?v?(\d+(?:\.\d+)*)")


def numeric_version(version: str) -> tuple[int, tuple[int, ...]] | None:
    """Epoch and leading numeric part: "1:2.3.0-rc1" -> (1, (2, 3)). None if not starting with a digit."""
    match = _NUMERIC_VERSION_RE.match(version.strip())
    if not match:
        return None
    parts = [int(part) for part in match.group(2).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return int(match.group(1) or 0), tuple(parts)


def upgrade_target(installed: str, fixed: list[str]) -> list[str]:
    """Lowest fixed version that is not older than the installed one.

    Older fixes belong to other branches (e.g. 2.12.2 for log4j 2.14.1). Only the
    numeric part is compared, which works for any ecosystem; if any version does
    not start with a digit, all of them are returned.
    """
    current = numeric_version(installed)
    keyed = [(numeric_version(version), version) for version in fixed]
    if current is None or any(key is None for key, _ in keyed):
        return fixed
    candidates = [(key, version) for key, version in keyed if key >= current]
    if not candidates:
        return fixed
    return [min(candidates, key=lambda item: item[0])[1]]


def vuln_cves(vuln_id: str, data: dict[str, Any]) -> list[str]:
    candidates = [vuln_id]
    for key in ("aliases", "upstream"):
        values = data.get(key)
        if isinstance(values, list):
            candidates.extend(value for value in values if isinstance(value, str))
    return sorted({value for value in candidates if CVE_RE.match(value)})


def vuln_summary(data: dict[str, Any]) -> str:
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        details = data.get("details")
        summary = details.strip().splitlines()[0] if isinstance(details, str) and details.strip() else ""
    return clean(summary.strip())[:300]


def _string_list(data: dict[str, Any], key: str) -> list[str]:
    values = data.get(key)
    return [value for value in values if isinstance(value, str)] if isinstance(values, list) else []


def vuln_names(vuln_id: str, data: dict[str, Any]) -> set[str]:
    """Every identifier of the vulnerability: its ID, its aliases, and its CVEs."""
    return {vuln_id, *_string_list(data, "aliases"), *vuln_cves(vuln_id, data)}


def is_malicious(vuln_id: str, data: dict[str, Any]) -> bool:
    if any(name.startswith(MALICIOUS_ID_PREFIX) for name in vuln_names(vuln_id, data)):
        return True
    database_specific = data.get("database_specific")
    return isinstance(database_specific, dict) and MALICIOUS_CWE in _string_list(database_specific, "cwe_ids")


@dataclass(frozen=True)
class CvssInfo:
    score: float | None
    vectors: list[str]
    # Qualitative severity from the database (e.g. GHSA "HIGH"); only used for
    # prioritization when no score can be computed.
    label: str | None


def cvss_info(data: dict[str, Any], package: PackageRef) -> CvssInfo:
    entries = list(data.get("severity") or [])
    for affected in _affected_for(data, package):
        entries.extend(affected.get("severity") or [])
    scores: list[float] = []
    vectors: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        severity_type, vector = entry.get("type"), entry.get("score")
        if not isinstance(severity_type, str) or not isinstance(vector, str):
            continue
        if severity_type.startswith("CVSS") and clean(vector) not in vectors:
            vectors.append(clean(vector))
        score = cvss_base_score(severity_type, vector)
        if score is not None:
            scores.append(score)
    database_specific = data.get("database_specific")
    label = database_specific.get("severity") if isinstance(database_specific, dict) else None
    label = clean(label).upper() if isinstance(label, str) and label.strip() else None
    return CvssInfo(max(scores) if scores else None, vectors, label)


_LABEL_RANK = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def merge_cvss(infos: list[CvssInfo]) -> CvssInfo:
    """Combines the severity of duplicate records, keeping the highest."""
    scores = [info.score for info in infos if info.score is not None]
    vectors = list(dict.fromkeys(vector for info in infos for vector in info.vectors))
    labels = [info.label for info in infos if info.label]
    label = max(labels, key=lambda value: _LABEL_RANK.get(value, 0)) if labels else None
    return CvssInfo(max(scores) if scores else None, vectors, label)


# --- KEV and EPSS ------------------------------------------------------------


@dataclass(frozen=True)
class KevEntry:
    date_added: str
    ransomware: str


def load_kev(client: HttpClient) -> dict[str, KevEntry]:
    """Downloads the catalog on every run: a newly added CVE changes the priority."""
    data = client.get_json(KEV_URL)
    if not _is_kev_catalog(data):
        raise ApiError("unexpected KEV catalog format")
    index: dict[str, KevEntry] = {}
    for entry in data["vulnerabilities"]:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cveID")
        if isinstance(cve, str) and CVE_RE.match(cve):
            index[cve] = KevEntry(
                clean(entry.get("dateAdded") or ""), clean(entry.get("knownRansomwareCampaignUse") or "")
            )
    return index


def _is_kev_catalog(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list)


@dataclass(frozen=True)
class EpssEntry:
    score: float
    percentile: float


def load_epss(client: HttpClient, cves: Iterable[str]) -> dict[str, EpssEntry]:
    valid = sorted({cve for cve in cves if CVE_RE.match(cve)})
    result: dict[str, EpssEntry] = {}
    for start in range(0, len(valid), EPSS_BATCH_SIZE):
        chunk = valid[start : start + EPSS_BATCH_SIZE]
        response = client.get_json(f"{EPSS_URL}?cve={','.join(chunk)}&limit={len(chunk)}")
        rows = response.get("data") if isinstance(response, dict) else None
        if not isinstance(rows, list):
            raise ApiError("unexpected response from EPSS")
        for row in rows:
            if not isinstance(row, dict) or row.get("cve") not in chunk:
                continue
            try:
                score, percentile = float(row["epss"]), float(row["percentile"])
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= score <= 1 and 0 <= percentile <= 1:
                result[row["cve"]] = EpssEntry(score, percentile)
    return result


# --- Findings and priority ---------------------------------------------------


@dataclass
class Finding:
    package: PackageRef
    vuln_id: str
    summary: str
    cves: list[str]
    cvss: CvssInfo
    epss: EpssEntry | None
    kev: KevEntry | None
    fixed_versions: list[str]
    malicious: bool = False
    # Other OSV IDs for the same vulnerability (e.g. the PYSEC of a GHSA).
    related_ids: list[str] = field(default_factory=list)
    priority: str = ""

    @property
    def upgrade_to(self) -> list[str]:
        return upgrade_target(self.package.version, self.fixed_versions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "package": self.package.label,
            "purl": self.package.purl,
            "id": self.vuln_id,
            "related_ids": self.related_ids,
            "malicious": self.malicious,
            "summary": self.summary,
            "cves": self.cves,
            "cvss": {"score": self.cvss.score, "vectors": self.cvss.vectors, "label": self.cvss.label},
            "epss": {"score": self.epss.score, "percentile": self.epss.percentile} if self.epss else None,
            "kev": {
                "in_kev": self.kev is not None,
                "date_added": self.kev.date_added if self.kev else None,
                "known_ransomware_campaign_use": self.kev.ransomware if self.kev else None,
            },
            "fixed_versions": self.fixed_versions,
            "upgrade_to": self.upgrade_to,
        }


def assign_priority(
    has_cve: bool, in_kev: bool, epss_percentile: float | None, cvss: CvssInfo, malicious: bool = False
) -> str:
    # An installed malicious package is already a compromise: scores do not matter.
    if malicious or (has_cve and in_kev):
        return PRIORITY_CRITICAL
    if cvss.score is not None:
        critical, high = cvss.score >= 9, cvss.score >= 7
    else:
        critical, high = cvss.label == "CRITICAL", cvss.label in ("CRITICAL", "HIGH")
    if (epss_percentile is not None and epss_percentile >= 0.95) or critical:
        return PRIORITY_HIGH
    if high:
        return PRIORITY_MEDIUM
    return PRIORITY_LOW if has_cve else PRIORITY_NO_DATA


def build_findings(
    vulns_by_package: dict[PackageRef, dict[str, str]],
    details: dict[str, dict[str, Any]],
    kev: dict[str, KevEntry],
    epss: dict[str, EpssEntry],
) -> list[Finding]:
    findings = []
    for package, vuln_ids in vulns_by_package.items():
        for group in group_duplicates(vuln_ids, details):
            findings.append(_merged_finding(package, group, details, kev, epss))
    findings.sort(key=_sort_key)
    return findings


def group_duplicates(vuln_ids: Iterable[str], details: dict[str, dict[str, Any]]) -> list[list[str]]:
    """Groups the IDs of one package that are the same vulnerability (alias or shared CVE).

    All malware advisories for a package go together: they describe the same
    problem and the fix is the same (remove the package).
    """
    parent: dict[str, str] = {}

    def root(vuln_id: str) -> str:
        while parent[vuln_id] != vuln_id:
            parent[vuln_id] = parent[parent[vuln_id]]
            vuln_id = parent[vuln_id]
        return vuln_id

    owner_by_name: dict[str, str] = {}
    for vuln_id in vuln_ids:
        parent[vuln_id] = vuln_id
        for name in sorted(vuln_names(vuln_id, details.get(vuln_id, {}))):
            if name in owner_by_name:
                parent[root(vuln_id)] = root(owner_by_name[name])
            else:
                owner_by_name[name] = vuln_id
    malicious = [vuln_id for vuln_id in parent if is_malicious(vuln_id, details.get(vuln_id, {}))]
    for vuln_id in malicious[1:]:
        parent[root(vuln_id)] = root(malicious[0])
    groups: dict[str, list[str]] = {}
    for vuln_id in parent:
        groups.setdefault(root(vuln_id), []).append(vuln_id)
    return [sorted(group, key=_primary_rank) for group in groups.values()]


def _primary_rank(vuln_id: str) -> tuple[int, str]:
    """GHSA is usually the most complete record; the order is stable across runs."""
    if vuln_id.startswith("GHSA-"):
        return (0, vuln_id)
    return (1 if CVE_RE.match(vuln_id) else 2, vuln_id)


def _merged_finding(
    package: PackageRef,
    group: list[str],
    details: dict[str, dict[str, Any]],
    kev: dict[str, KevEntry],
    epss: dict[str, EpssEntry],
) -> Finding:
    records = [(vuln_id, details.get(vuln_id, {})) for vuln_id in group]
    cves = sorted({cve for vuln_id, data in records for cve in vuln_cves(vuln_id, data)})
    kev_hits = [kev[cve] for cve in cves if cve in kev]
    epss_hits = [epss[cve] for cve in cves if cve in epss]
    finding = Finding(
        package=package,
        vuln_id=group[0],
        summary=next((s for s in (vuln_summary(data) for _, data in records) if s), ""),
        cves=cves,
        cvss=merge_cvss([cvss_info(data, package) for _, data in records]),
        epss=max(epss_hits, key=lambda e: e.percentile) if epss_hits else None,
        kev=min(kev_hits, key=lambda e: e.date_added) if kev_hits else None,
        fixed_versions=list(dict.fromkeys(v for _, data in records for v in fixed_versions(data, package))),
        malicious=any(is_malicious(vuln_id, data) for vuln_id, data in records),
        related_ids=group[1:],
    )
    finding.priority = assign_priority(
        bool(cves),
        finding.kev is not None,
        finding.epss.percentile if finding.epss else None,
        finding.cvss,
        finding.malicious,
    )
    return finding


def _sort_key(finding: Finding) -> tuple[Any, ...]:
    return (
        PRIORITY_ORDER.index(finding.priority),
        not finding.malicious,
        -(finding.epss.percentile if finding.epss else -1),
        -(finding.cvss.score if finding.cvss.score is not None else -1),
        finding.package.label,
        finding.vuln_id,
    )


# --- Analysis ----------------------------------------------------------------


@dataclass(frozen=True)
class Coverage:
    analyzed_packages: int
    skipped_components: int
    # Packages with purl types OSV does not map: an empty result does not mean "clean".
    uncovered: list[PackageRef]

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzed_packages": self.analyzed_packages,
            "skipped_components": self.skipped_components,
            "uncovered_purls": [package.purl for package in self.uncovered],
        }


def coverage_of(scan: SbomScan, vulns_by_package: dict[PackageRef, dict[str, str]]) -> Coverage:
    uncovered = [p for p in scan.packages if not p.osv_supported and not vulns_by_package.get(p)]
    by_type: dict[str, int] = {}
    for package in uncovered:
        purl_type = package.parsed.type
        if purl_type in OSV_DISTRO_NAMESPACES:
            purl_type = f"{purl_type}/{package.parsed.namespace}"
        by_type[purl_type] = by_type.get(purl_type, 0) + 1
    for purl_type, count in sorted(by_type.items()):
        logger.warning(
            "%s: OSV does not cover purl type %s: %d packages not analyzed", scan.source, clean(purl_type), count
        )
    return Coverage(len(scan.packages) - len(uncovered), scan.skipped_components, uncovered)


@dataclass(frozen=True)
class Report:
    source: str
    coverage: Coverage
    findings: list[Finding]

    def to_dict(self, generated_at: str) -> dict[str, Any]:
        return {
            "format_version": FORMAT_VERSION,
            "tool": {"name": TOOL_NAME, "version": __version__, "url": PROJECT_URL},
            "generated_at": generated_at,
            "sbom": self.source,
            "coverage": self.coverage.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def analyze(scans: list[SbomScan], client: HttpClient, cache: DiskCache) -> list[Report]:
    """Looks up the packages of every SBOM with a single round of queries."""
    packages = list(dict.fromkeys(package for scan in scans for package in scan.packages))
    logger.info("%d unique packages with purl and version", len(packages))
    vulns_by_package = query_osv(client, packages) if packages else {}

    modified_by_id: dict[str, str] = {}
    for vulns in vulns_by_package.values():
        modified_by_id.update(vulns)
    logger.info("%d distinct vulnerabilities; fetching details", len(modified_by_id))
    details = fetch_vuln_details(client, cache, modified_by_id)
    for vulns in vulns_by_package.values():
        for vuln_id in [vuln_id for vuln_id in vulns if vuln_id not in details]:
            del vulns[vuln_id]

    all_cves = {cve for vid in modified_by_id for cve in vuln_cves(vid, details.get(vid, {}))}
    kev = load_kev(client) if all_cves else {}
    epss = load_epss(client, all_cves)

    reports = []
    for scan in scans:
        own = {package: vulns_by_package.get(package, {}) for package in scan.packages}
        reports.append(Report(scan.source, coverage_of(scan, own), build_findings(own, details, kev, epss)))
    return reports


# --- Output ------------------------------------------------------------------

TABLE_HEADERS = ("PRIORITY", "PACKAGE@VERSION", "ID", "CVE", "CVSS", "EPSS", "KEV", "FIXED IN")
MAX_CELL_WIDTH = 40


def _truncate(text: str, width: int = MAX_CELL_WIDTH, keep_end: bool = False) -> str:
    if len(text) <= width:
        return text
    return "..." + text[3 - width :] if keep_end else text[: width - 3] + "..."


def _format_row(finding: Finding) -> list[str]:
    has_cve = bool(finding.cves)
    if finding.cvss.score is not None:
        cvss = f"{finding.cvss.score:.1f}"
    else:
        cvss = f"({finding.cvss.label})" if finding.cvss.label else "-"
    if not has_cve:
        epss = kev = "n/a"
    else:
        epss = f"{finding.epss.score:.3f} p{finding.epss.percentile * 100:.0f}" if finding.epss else "-"
        if finding.kev:
            ransomware = " ransomware" if finding.kev.ransomware.lower() == "known" else ""
            kev = f"YES {finding.kev.date_added}{ransomware}"
        else:
            kev = "no"
    row = [
        f"{finding.priority} malware" if finding.malicious else finding.priority,
        finding.package.label,
        f"{finding.vuln_id} +{len(finding.related_ids)}" if finding.related_ids else finding.vuln_id,
        ", ".join(finding.cves) or "-",
        cvss,
        epss,
        kev,
        ", ".join(finding.upgrade_to) or "-",
    ]
    # The package is truncated on the left so name@version is not lost.
    return [_truncate(clean(cell), keep_end=(index == 1)) for index, cell in enumerate(row)]


def render_table(findings: list[Finding]) -> str:
    headers = list(TABLE_HEADERS)
    rows = [_format_row(finding) for finding in findings]
    widths = [max(len(row[i]) for row in [headers, *rows]) for i in range(len(headers))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in [headers, *rows]]
    lines.insert(1, "  ".join("-" * width for width in widths))
    return "\n".join(lines)


def priority_counts(findings: list[Finding]) -> str:
    counts = [f"{p}: {sum(f.priority == p for f in findings)}" for p in PRIORITY_ORDER]
    return ", ".join(counts)


def print_report(report: Report) -> None:
    coverage = report.coverage
    if report.findings:
        print(render_table(report.findings))
        print()
        print(f"Findings by priority: {priority_counts(report.findings)}")
    else:
        print("No known vulnerabilities in the analyzed packages.")
    print(f"Packages analyzed: {coverage.analyzed_packages}.")
    if coverage.skipped_components or coverage.uncovered:
        print(
            f"Not analyzed: {coverage.skipped_components} components without a purl or version"
            f" and {len(coverage.uncovered)} packages with purl types OSV does not cover (see warnings)."
        )


def print_reports(reports: list[Report], inputs: Inputs, directory_mode: bool) -> None:
    if not directory_mode:
        print_report(reports[0])
        return
    for report in reports:
        print(f"== {clean(report.source)} ==")
        print_report(report)
        print()
    findings = [finding for report in reports for finding in report.findings]
    print(
        f"SBOMs analyzed: {len(reports)}. Files skipped (not a CycloneDX JSON SBOM): {inputs.skipped_files}."
        f" SBOMs that could not be analyzed: {len(inputs.failed_files)}."
    )
    if inputs.failed_files:
        print(f"Could not analyze (see errors): {', '.join(inputs.failed_files)}")
    print(f"Total findings by priority: {priority_counts(findings)}")


def output_file_name(source: str, used: set[str]) -> str:
    """<name>.triage.json, without the trailing .json of the SBOM name.

    If two SBOMs would get the same name (e.g. "app" and "app.json"), the full name is kept.
    """
    base = source[: -len(".json")] if source.lower().endswith(".json") else source
    name = f"{base}{OUTPUT_SUFFIX}"
    if name in used:
        name = f"{source}{OUTPUT_SUFFIX}"
    used.add(name)
    return name


def write_reports(output_dir: Path, reports: list[Report], generated_at: str) -> None:
    used: set[str] = set()
    for report in reports:
        write_json_atomic(output_dir / output_file_name(report.source, used), report.to_dict(generated_at))
    logger.info("%d JSON reports written to %s", len(reports), output_dir)


# --- CLI ---------------------------------------------------------------------


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Looks up known vulnerabilities (OSV + CISA KEV + EPSS) in CycloneDX JSON SBOMs.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("sbom", nargs="?", type=Path, help="CycloneDX JSON SBOM file")
    source.add_argument(
        "--input-dir",
        type=Path,
        metavar="DIR",
        help="analyze every CycloneDX JSON SBOM directly inside DIR (subdirectories are not read;"
        " other files are skipped)",
    )
    parser.add_argument(
        "--json", metavar="FILE", help="write the findings as JSON to FILE ('-' = stdout); single SBOM only"
    )
    parser.add_argument("--output-dir", type=Path, metavar="DIR", help="write one <name>.triage.json per SBOM to DIR")
    parser.add_argument(
        "--fail-on",
        type=_fail_on_priority,
        metavar="PRIORITY",
        help=f"exit with code {EXIT_FAIL_ON} if any finding has this priority or higher"
        f" ({', '.join(FAIL_ON_CHOICES)})",
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=Path(".cache"), help="cache directory for OSV details (default: .cache)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if args.input_dir and args.json:
        parser.error("--json cannot be used with --input-dir; use --output-dir")
    if args.input_dir and args.output_dir and _same_directory(args.input_dir, args.output_dir):
        parser.error("--output-dir must be different from --input-dir")
    return args


def _same_directory(first: Path, second: Path) -> bool:
    return first.resolve() == second.resolve()


def _fail_on_priority(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in FAIL_ON_CHOICES:
        raise argparse.ArgumentTypeError(f"use one of: {', '.join(FAIL_ON_CHOICES)}")
    return FAIL_ON_CHOICES[normalized]


def reaches_threshold(findings: list[Finding], threshold: str) -> bool:
    limit = PRIORITY_ORDER.index(threshold)
    return any(PRIORITY_ORDER.index(finding.priority) <= limit for finding in findings)


def run(args: argparse.Namespace, client: HttpClient | None = None) -> int:
    client = client or HttpClient()
    cache = DiskCache(args.cache_dir)
    if args.input_dir:
        inputs = load_directory(args.input_dir)
    else:
        inputs = Inputs([extract_packages(read_sbom(args.sbom), args.sbom.name)])
    reports = analyze(inputs.scans, client, cache)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if args.output_dir:
        write_reports(args.output_dir, reports, generated_at)
    if args.json == "-":
        json.dump(reports[0].to_dict(generated_at), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        if args.json:
            write_json_atomic(Path(args.json), reports[0].to_dict(generated_at))
        print_reports(reports, inputs, directory_mode=bool(args.input_dir))

    # An SBOM that could not be analyzed means the results are incomplete, which matters
    # more than any finding, so it takes precedence over --fail-on.
    if inputs.failed_files:
        logger.error("%d SBOMs could not be analyzed: %s", len(inputs.failed_files), ", ".join(inputs.failed_files))
        return EXIT_SBOM_FAILED
    findings = [finding for report in reports for finding in report.findings]
    if args.fail_on and reaches_threshold(findings, args.fail_on):
        logger.info("there are findings with priority %s or higher (--fail-on)", args.fail_on)
        return EXIT_FAIL_ON
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = parse_args(argv)
    try:
        return run(args)
    except (SbomError, ApiError) as error:
        logger.error("%s", error)
    except OSError as error:
        logger.error("could not write to %s", error.filename or "disk")
    except KeyboardInterrupt:
        return 130
    return 1


if __name__ == "__main__":
    sys.exit(main())

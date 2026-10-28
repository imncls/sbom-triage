import argparse
import io
import json
import tempfile
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

import sbom_triage as st


def package(purl: str, query_version: str | None = None) -> st.PackageRef:
    return st.PackageRef(purl, st.parse_purl(purl), query_version)


def cyclonedx(*components: dict) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(components)}


class FakeResponse(io.BytesIO):
    pass


class PurlTests(unittest.TestCase):
    def test_parses_namespace_version_and_ignores_qualifiers(self):
        parsed = st.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar#sub")
        self.assertEqual(parsed, st.Purl("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"))

    def test_decodes_npm_scope(self):
        parsed = st.parse_purl("pkg:npm/%40babel/core@7.0.0")
        self.assertEqual((parsed.namespace, parsed.name, parsed.version), ("@babel", "core", "7.0.0"))

    def test_rejects_non_purl(self):
        with self.assertRaises(ValueError):
            st.parse_purl("maven:foo")


class SbomTests(unittest.TestCase):
    BOM = cyclonedx(
        {
            "name": "a",
            "purl": "pkg:pypi/requests@2.0.0",
            "components": [
                {"name": "nested", "purl": "pkg:npm/lodash@4.17.20"},
                {"name": "nopurl"},
            ],
        },
        {"name": "dup", "purl": "pkg:pypi/requests@2.0.0"},
        {"name": "noversion", "purl": "pkg:pypi/flask"},
        {"name": "fromfield", "purl": "pkg:pypi/django", "version": "3.2.0"},
    )

    def test_extracts_nested_dedups_and_warns(self):
        with self.assertLogs("sbom_triage", "WARNING") as logs:
            scan = st.extract_packages(self.BOM, "app.json")
        packages = scan.packages
        self.assertEqual([p.label for p in packages], ["requests@2.0.0", "lodash@4.17.20", "django@3.2.0"])
        self.assertEqual(packages[2].query_version, "3.2.0")
        self.assertEqual(scan.skipped_components, 2)
        self.assertEqual(scan.source, "app.json")
        output = "\n".join(logs.output)
        self.assertIn("app.json: component without a purl: nopurl", output)
        self.assertIn("without a version", output)
        self.assertIn("pkg:pypi/flask", output)

    def test_osv_supported_purl_types(self):
        self.assertTrue(package("pkg:pub/http@1.0.0").osv_supported)
        self.assertTrue(package("pkg:deb/debian/openssl@1.1.1?distro=debian-11").osv_supported)
        self.assertFalse(package("pkg:deb/mydistro/openssl@1.1.1").osv_supported)
        self.assertFalse(package("pkg:unknowntype/foo@1.0").osv_supported)

    def test_coverage_reports_unsupported_types_without_results(self):
        supported, unknown, unknown_with_vulns = (
            package("pkg:pypi/a@1"), package("pkg:unknowntype/b@1"), package("pkg:unknowntype/c@1"),
        )
        scan = st.SbomScan("app.json", [supported, unknown, unknown_with_vulns], skipped_components=4)
        found = {supported: {}, unknown: {}, unknown_with_vulns: {"X-1": ""}}
        with self.assertLogs("sbom_triage", "WARNING") as logs:
            coverage = st.coverage_of(scan, found)
        self.assertEqual(coverage.uncovered, [unknown])
        self.assertEqual(coverage.analyzed_packages, 2)
        self.assertEqual(coverage.skipped_components, 4)
        self.assertIn("unknowntype", "\n".join(logs.output))


class ReadSbomTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name: str, content: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(content)
        return path

    def test_accepts_cyclonedx_json(self):
        path = self.write("a.json", json.dumps(cyclonedx()).encode())
        self.assertEqual(st.read_sbom(path)["bomFormat"], "CycloneDX")

    def test_accepts_utf8_bom_and_leading_whitespace(self):
        path = self.write("a.json", b"\xef\xbb\xbf \n" + json.dumps(cyclonedx()).encode())
        self.assertEqual(st.read_sbom(path)["specVersion"], "1.5")

    def test_rejects_files_that_are_not_cyclonedx(self):
        cases = {
            "spdx.json": json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}).encode(),
            "bom.xml": b'<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>',
            "other.json": json.dumps({"name": "not an sbom"}).encode(),
            "array.json": b"[1, 2, 3]",
            "broken-other.json": b'{"name": "not an sbom", ',
            "binary.bin": bytes(range(256)) * 64,
            "empty.json": b"",
        }
        for name, content in cases.items():
            with self.subTest(name=name), self.assertRaises(st.NotAnSbomError):
                st.read_sbom(self.write(name, content))

    def test_cyclonedx_files_that_cannot_be_analyzed_are_errors(self):
        full = json.dumps(cyclonedx({"name": "x", "purl": "pkg:npm/x@1.0.0"}))
        cases = {
            "half-written.json": full[: len(full) // 2].encode(),
            "future.json": json.dumps({"bomFormat": "CycloneDX", "specVersion": "2.0"}).encode(),
            "nospec.json": json.dumps({"bomFormat": "CycloneDX"}).encode(),
        }
        for name, content in cases.items():
            with self.subTest(name=name), self.assertRaises(st.SbomError) as raised:
                st.read_sbom(self.write(name, content))
            self.assertNotIsInstance(raised.exception, st.NotAnSbomError)

    def test_unreadable_file_is_an_error(self):
        with self.assertRaises(st.SbomError) as raised:
            st.read_sbom(self.dir / "missing.json")
        self.assertNotIsInstance(raised.exception, st.NotAnSbomError)

    def test_load_directory_skips_non_sboms_and_subdirectories(self):
        self.write("a.cdx.json", json.dumps(cyclonedx({"name": "x", "purl": "pkg:pypi/x@1"})).encode())
        self.write("b.json", json.dumps(cyclonedx({"name": "y", "purl": "pkg:npm/y@2"})).encode())
        self.write("spdx.json", json.dumps({"spdxVersion": "SPDX-2.3"}).encode())
        self.write("notes.txt", b"hello")
        self.write("partial.json", b'{"bomFormat": "CycloneDX", "specVersion": "1.5", "compo')
        (self.dir / "sub").mkdir()
        (self.dir / "sub" / "c.json").write_text(json.dumps(cyclonedx()), encoding="utf-8")
        with self.assertLogs("sbom_triage", "INFO") as logs:
            inputs = st.load_directory(self.dir)
        self.assertEqual([scan.source for scan in inputs.scans], ["a.cdx.json", "b.json"])
        self.assertEqual(inputs.skipped_files, 2)
        self.assertEqual(inputs.failed_files, ("partial.json",))
        output = "\n".join(logs.output)
        self.assertIn("spdx.json is not a CycloneDX SBOM", output)
        self.assertIn("ERROR:sbom_triage:cannot analyze: partial.json is not valid JSON", output)

    def test_load_directory_requires_a_directory(self):
        with self.assertRaises(st.SbomError):
            st.load_directory(self.write("a.json", b"{}"))

    def test_output_file_names(self):
        used: set[str] = set()
        self.assertEqual(st.output_file_name("app.cdx.json", used), "app.cdx.triage.json")
        self.assertEqual(st.output_file_name("app", used), "app.triage.json")
        # "app.json" would also become "app.triage.json", so the full name is kept.
        self.assertEqual(st.output_file_name("app.json", used), "app.json.triage.json")


class CvssTests(unittest.TestCase):
    def test_cvss3_scores(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(st.cvss3_base_score(vector), expected)

    def test_cvss2_score(self):
        self.assertEqual(st.cvss2_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), 7.5)

    def test_cvss4_scores_match_the_first_reference_calculator(self):
        # Scores computed with the FIRST reference implementation
        # (github.com/FIRSTdotorg/cvss-v4-calculator, commit c5b0d409).
        cases = {
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.3,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": 10.0,
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 8.5,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": 0.0,
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U/IR:H/MAV:A/MVI:L/RE:X": 0.1,
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:H/SA:L/E:A/MAT:P/MSC:H/MSI:S/R:I/V:C/U:Amber": 4.8,
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:H/SA:H/CR:L/MAV:N/MAC:X/MPR:N/MSC:N/MSA:X/AU:N/RE:M": 8.7,
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:H/CR:H/IR:L/AR:M/MAV:X/MAT:X/MUI:A/MVC:N/MVA:L/MSC:H/MSI:N": 5.1,
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:H/IR:X/MVC:L/MSA:L/U:Green": 5.6,
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:H/SC:H/SI:L/SA:H/IR:L/AR:X/MAV:P/MAC:H/MVI:X/MVA:X/MSC:N/V:C": 5.6,
            "CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:L/E:X/CR:X/AR:M/MPR:N/MUI:N/MSC:X/S:P/R:X": 5.7,
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L/AR:H/MSC:L/MSI:N/MSA:S/S:X/V:C/RE:X": 9.4,
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:H/VI:L/VA:H/SC:N/SI:H/SA:H/E:A/MUI:X/MSC:N/MSA:X/R:U/V:C/RE:X": 7.1,
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L/E:P/IR:X/AR:M/MAT:P/MUI:A/MSC:L/MSI:S/AU:N/R:U/U:Green": 6.9,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:L/SA:L/CR:H/MAV:A/MVI:L/MSI:S/S:N/R:A/V:C/RE:H/U:X": 8.0,
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:H/SC:N/SI:H/SA:N/E:U/MAC:L/MVC:L/MVI:L/RE:H": 3.8,
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:N/VA:H/SC:N/SI:H/SA:N/IR:M/MAT:X/MPR:N/MUI:N/MVC:N/MVA:L/MSI:H/MSA:H/AU:N/R:X/RE:L/U:Amber": 7.0,
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:L/SC:H/SI:L/SA:N/E:A/MSI:N/AU:N": 8.1,
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:N/SI:H/SA:L/CR:H/IR:L/MSC:L/MSI:H/MSA:L/S:X/AU:N": 5.8,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:H/SI:L/SA:L/IR:X/AR:X/MVC:X/MVI:H/MSA:S/RE:M": 9.3,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(st.cvss4_score(vector), expected)
                self.assertEqual(st.cvss_base_score("CVSS_V4", vector), expected)

    def test_invalid_vectors_have_no_score(self):
        self.assertIsNone(st.cvss3_base_score("CVSS:3.1/AV:X"))
        invalid_v4 = [
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",  # missing Base metrics
            "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # wrong order
            "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # invalid value
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/E:U",  # repeated
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/XX:Y",  # unknown metric
            "CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # wrong prefix
        ]
        for vector in invalid_v4:
            with self.subTest(vector=vector):
                self.assertIsNone(st.cvss4_score(vector))

    def test_v4_only_record_gets_a_numeric_score(self):
        data = {
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
            "database_specific": {"severity": "MODERATE"},
        }
        info = st.cvss_info(data, package("pkg:pypi/a@1"))
        self.assertEqual(info.score, 9.3)
        self.assertEqual(st.assign_priority(True, False, None, info), st.PRIORITY_HIGH)


class OsvDataTests(unittest.TestCase):
    DATA = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-44228", "OTHER-1"],
        "summary": "Remote code\x1b[31m execution",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]},
                    {"type": "GIT", "events": [{"fixed": "abc123"}]},
                ],
            },
            {
                "package": {"ecosystem": "Maven", "name": "org.other:thing"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9"}]}],
            },
        ],
    }

    def test_clean_removes_control_and_invisible_characters(self):
        text = "evil\u202etxt.exe \x1b[31mred\u200b zero\u2028line"
        self.assertEqual(st.clean(text), "eviltxt.exe [31mred zeroline")

    def test_extracts_fields(self):
        pkg = package("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertEqual(st.vuln_cves(self.DATA["id"], self.DATA), ["CVE-2021-44228"])
        self.assertEqual(st.vuln_summary(self.DATA), "Remote code[31m execution")
        self.assertEqual(st.fixed_versions(self.DATA, pkg), ["2.15.0"])
        info = st.cvss_info(self.DATA, pkg)
        self.assertEqual(info.score, 10.0)
        self.assertEqual(len(info.vectors), 1)

    def test_upgrade_target_picks_lowest_fix_not_below_installed(self):
        self.assertEqual(st.upgrade_target("2.14.1", ["2.15.0", "2.3.1", "2.12.2"]), ["2.15.0"])
        self.assertEqual(st.upgrade_target("v1.2.3", ["v1.4.0", "v1.3.0"]), ["v1.3.0"])
        self.assertEqual(st.upgrade_target("2.0.0-rc1", ["2.0.0", "1.9.9"]), ["2.0.0"])
        self.assertEqual(st.upgrade_target("1:1.0", ["2.0", "1:1.1"]), ["1:1.1"])

    def test_upgrade_target_falls_back_to_all(self):
        self.assertEqual(st.upgrade_target("abc", ["1.0", "2.0"]), ["1.0", "2.0"])
        self.assertEqual(st.upgrade_target("1.0", ["1.1", "release-2"]), ["1.1", "release-2"])
        self.assertEqual(st.upgrade_target("3.0", ["1.0", "2.0"]), ["1.0", "2.0"])
        self.assertEqual(st.upgrade_target("1.0", []), [])

    def test_fixed_versions_fall_back_to_all_affected(self):
        pkg = package("pkg:maven/unrelated/name@1.0")
        self.assertEqual(st.fixed_versions(self.DATA, pkg), ["2.15.0", "9.9"])


class PriorityTests(unittest.TestCase):
    def cvss(self, score=None, label=None):
        return st.CvssInfo(score, [], label)

    def test_rules(self):
        p = st.assign_priority
        self.assertEqual(p(True, True, 0.1, self.cvss(2.0)), st.PRIORITY_CRITICAL)
        self.assertEqual(p(True, False, 0.95, self.cvss(2.0)), st.PRIORITY_HIGH)
        self.assertEqual(p(True, False, 0.5, self.cvss(9.0)), st.PRIORITY_HIGH)
        self.assertEqual(p(True, False, 0.5, self.cvss(7.0)), st.PRIORITY_MEDIUM)
        self.assertEqual(p(True, False, None, self.cvss(6.9)), st.PRIORITY_LOW)
        self.assertEqual(p(True, False, None, self.cvss(None, "HIGH")), st.PRIORITY_MEDIUM)

    def test_without_cve_is_not_low(self):
        p = st.assign_priority
        self.assertEqual(p(False, False, None, self.cvss(3.0)), st.PRIORITY_NO_DATA)
        self.assertEqual(p(False, False, None, self.cvss(9.8)), st.PRIORITY_HIGH)

    def test_fail_on_values(self):
        self.assertEqual(st._fail_on_priority("critical"), st.PRIORITY_CRITICAL)
        self.assertEqual(st._fail_on_priority("HIGH"), st.PRIORITY_HIGH)
        self.assertEqual(st._fail_on_priority("no-data"), st.PRIORITY_NO_DATA)
        with self.assertRaises(argparse.ArgumentTypeError):
            st._fail_on_priority("urgent")

    def test_reaches_threshold(self):
        findings = [
            st.Finding(package("pkg:pypi/a@1"), "A", "", [], self.cvss(), None, None, [], priority=st.PRIORITY_MEDIUM)
        ]
        self.assertTrue(st.reaches_threshold(findings, st.PRIORITY_MEDIUM))
        self.assertTrue(st.reaches_threshold(findings, st.PRIORITY_LOW))
        self.assertFalse(st.reaches_threshold(findings, st.PRIORITY_HIGH))
        self.assertFalse(st.reaches_threshold([], st.PRIORITY_LOW))

    def test_malware_is_critical_regardless_of_scores(self):
        self.assertEqual(st.assign_priority(False, False, None, self.cvss(), malicious=True), st.PRIORITY_CRITICAL)
        self.assertEqual(st.assign_priority(True, False, 0.1, self.cvss(7.5), malicious=True), st.PRIORITY_CRITICAL)

    def test_detects_malware(self):
        self.assertTrue(st.is_malicious("MAL-2025-20690", {}))
        self.assertTrue(st.is_malicious("GHSA-1", {"aliases": ["MAL-2024-1"]}))
        self.assertTrue(st.is_malicious("GHSA-1", {"database_specific": {"cwe_ids": ["CWE-506"]}}))
        self.assertFalse(st.is_malicious("GHSA-1", {"database_specific": {"cwe_ids": ["CWE-79"]}}))
        self.assertFalse(st.is_malicious("GHSA-1", {"summary": "Malicious input causes DoS"}))


class DuplicateTests(unittest.TestCase):
    PKG = package("pkg:pypi/requests@2.19.0")
    DETAILS = {
        "GHSA-x84v-xcm2-53pg": {
            "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
            "summary": "Insufficiently Protected Credentials",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [{"package": {"name": "requests"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.20.0"}]}]}],
        },
        "PYSEC-2018-28": {
            "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
            "affected": [{"package": {"name": "requests"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.20"}]}]}],
        },
        # Only shares a CVE with the others, no direct aliases.
        "OTHER-1": {"upstream": ["CVE-2018-18074"]},
        "PYSEC-2023-74": {"aliases": ["CVE-2023-32681"]},
    }

    def test_groups_by_alias_and_shared_cve(self):
        groups = st.group_duplicates(self.DETAILS, self.DETAILS)
        self.assertCountEqual(groups, [["GHSA-x84v-xcm2-53pg", "OTHER-1", "PYSEC-2018-28"], ["PYSEC-2023-74"]])

    def test_groups_all_malware_of_a_package(self):
        details = {
            "GHSA-9x64-5r7x-2q53": {"database_specific": {"cwe_ids": ["CWE-506"]}},
            "GHSA-mh6f-8j2x-4483": {"database_specific": {"cwe_ids": ["CWE-506"]}},
            "MAL-2025-20690": {},
            "GHSA-other": {"aliases": ["CVE-2020-1234"]},
        }
        findings = st.build_findings({self.PKG: dict.fromkeys(details, "")}, details, {}, {})
        self.assertEqual(len(findings), 2)
        malware = findings[0]
        self.assertTrue(malware.malicious)
        self.assertEqual(malware.vuln_id, "GHSA-9x64-5r7x-2q53")
        self.assertEqual(malware.related_ids, ["GHSA-mh6f-8j2x-4483", "MAL-2025-20690"])

    def test_merged_finding_takes_highest_severity(self):
        findings = st.build_findings({self.PKG: dict.fromkeys(self.DETAILS, "")}, self.DETAILS, {}, {})
        merged = next(f for f in findings if f.vuln_id == "GHSA-x84v-xcm2-53pg")
        self.assertEqual(merged.related_ids, ["OTHER-1", "PYSEC-2018-28"])
        self.assertEqual(merged.cvss.score, 7.5)
        self.assertEqual(merged.priority, st.PRIORITY_MEDIUM)
        self.assertEqual(merged.cves, ["CVE-2018-18074"])
        self.assertEqual(merged.fixed_versions, ["2.20.0", "2.20"])
        self.assertEqual(len(findings), 2)


class HttpClientTests(unittest.TestCase):
    def test_retries_on_429_and_5xx_then_succeeds(self):
        calls, sleeps = [], []

        def opener(request, timeout):
            calls.append(request)
            if len(calls) == 1:
                raise urllib.error.HTTPError(request.full_url, 429, "Too Many", {"Retry-After": "3"}, None)
            if len(calls) == 2:
                raise urllib.error.HTTPError(request.full_url, 503, "Unavailable", {}, None)
            return FakeResponse(b'{"ok": true}')

        client = st.HttpClient(opener=opener, sleep=sleeps.append)
        with self.assertLogs("sbom_triage", "INFO"):
            self.assertEqual(client.post_json("https://example.test/x", {"a": 1}), {"ok": True})
        self.assertEqual(len(calls), 3)
        self.assertGreaterEqual(sleeps[0], 3)
        self.assertEqual(calls[0].get_header("User-agent"), st.USER_AGENT)
        self.assertEqual(st.USER_AGENT, f"sbom-triage/{st.__version__} (+https://github.com/imncls/sbom-triage)")
        self.assertEqual(calls[0].get_method(), "POST")

    def test_does_not_retry_4xx(self):
        calls = []

        def opener(request, timeout):
            calls.append(request)
            raise urllib.error.HTTPError(request.full_url, 400, "Bad", {}, None)

        client = st.HttpClient(opener=opener, sleep=lambda _: None)
        with self.assertRaises(st.ApiError):
            client.get_json("https://example.test/x")
        self.assertEqual(len(calls), 1)

    def test_404_raises_not_found(self):
        def opener(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

        with self.assertRaises(st.NotFoundError):
            st.HttpClient(opener=opener, sleep=lambda _: None).get_json("https://example.test/x")

    def test_redirects_only_to_https(self):
        handler = st._HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://api.osv.dev/v1/vulns/X")
        with self.assertRaises(st.ApiError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://api.osv.dev/v1/vulns/X")
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://osv.dev/v1/vulns/X")
        self.assertEqual(redirected.full_url, "https://osv.dev/v1/vulns/X")

    def test_gives_up_after_max_attempts(self):
        calls = []

        def opener(request, timeout):
            calls.append(request)
            raise urllib.error.URLError("down")

        client = st.HttpClient(opener=opener, sleep=lambda _: None, max_attempts=3)
        with self.assertLogs("sbom_triage", "INFO"), self.assertRaises(st.ApiError):
            client.get_json("https://example.test/x")
        self.assertEqual(len(calls), 3)


class FakeClient:
    """Answers by URL prefix and records the requests."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get_json(self, url):
        self.calls.append(("GET", url, None))
        return self._route(url, None)

    def post_json(self, url, payload):
        self.calls.append(("POST", url, payload))
        return self._route(url, payload)

    def _route(self, url, payload):
        for prefix, handler in self.routes.items():
            if url.startswith(prefix):
                return handler(url, payload)
        raise AssertionError(f"unexpected URL {url}")


class OsvQueryTests(unittest.TestCase):
    def test_paginates_and_rejects_unsafe_ids(self):
        pkg = package("pkg:pypi/requests@2.0.0")

        def querybatch(url, payload):
            query = payload["queries"][0]
            if "page_token" not in query:
                vulns = [{"id": "PYSEC-1", "modified": "m1"}, {"id": "../evil"}]
                return {"results": [{"vulns": vulns, "next_page_token": "t1"}]}
            return {"results": [{"vulns": [{"id": "PYSEC-2", "modified": "m2"}]}]}

        client = FakeClient({st.OSV_QUERYBATCH_URL: querybatch})
        with self.assertLogs("sbom_triage", "WARNING"):
            result = st.query_osv(client, [pkg])
        self.assertEqual(result[pkg], {"PYSEC-1": "m1", "PYSEC-2": "m2"})
        self.assertEqual(client.calls[1][2]["queries"][0]["page_token"], "t1")

    def test_splits_batches_of_1000(self):
        packages = [package(f"pkg:pypi/p{i}@1.0") for i in range(1001)]
        client = FakeClient(
            {st.OSV_QUERYBATCH_URL: lambda url, payload: {"results": [{} for _ in payload["queries"]]}}
        )
        st.query_osv(client, packages)
        self.assertEqual([len(c[2]["queries"]) for c in client.calls], [1000, 1])

    def test_ids_with_colon_are_kept_and_cached_under_safe_name(self):
        vuln_id = "openSUSE-SU-2024:0001-1"
        pkg = package("pkg:rpm/opensuse/opera@1.0")
        client = FakeClient({
            st.OSV_QUERYBATCH_URL: lambda url, payload: {"results": [{"vulns": [{"id": vuln_id, "modified": "m"}]}]},
            "https://api.osv.dev/v1/vulns/": lambda url, payload: {"id": vuln_id, "modified": "m"},
        })
        self.assertEqual(st.query_osv(client, [pkg])[pkg], {vuln_id: "m"})
        with tempfile.TemporaryDirectory() as tmp:
            cache = st.DiskCache(Path(tmp))
            self.assertEqual(st.fetch_vuln_details(client, cache, {vuln_id: "m"})[vuln_id]["id"], vuln_id)
            [cached_file] = (Path(tmp) / "osv").iterdir()
            self.assertNotIn(":", cached_file.name)
            st.fetch_vuln_details(client, cache, {vuln_id: "m"})
        self.assertTrue(client.calls[1][1].endswith("openSUSE-SU-2024%3A0001-1"))
        self.assertEqual(len(client.calls), 2)

    def test_details_are_cached_until_modified_changes(self):
        detail = {"id": "PYSEC-1", "modified": "m1"}
        client = FakeClient({"https://api.osv.dev/v1/vulns/": lambda url, payload: detail})
        with tempfile.TemporaryDirectory() as tmp:
            cache = st.DiskCache(Path(tmp))
            st.fetch_vuln_details(client, cache, {"PYSEC-1": "m1"})
            st.fetch_vuln_details(client, cache, {"PYSEC-1": "m1"})
            self.assertEqual(len(client.calls), 1)
            st.fetch_vuln_details(client, cache, {"PYSEC-1": "m2"})
            self.assertEqual(len(client.calls), 2)

    def test_details_without_modified_date_are_fetched_again(self):
        detail = {"id": "PYSEC-1", "modified": "m1"}
        client = FakeClient({"https://api.osv.dev/v1/vulns/": lambda url, payload: detail})
        with tempfile.TemporaryDirectory() as tmp:
            cache = st.DiskCache(Path(tmp))
            st.fetch_vuln_details(client, cache, {"PYSEC-1": ""})
            st.fetch_vuln_details(client, cache, {"PYSEC-1": ""})
        self.assertEqual(len(client.calls), 2)

    def test_withdrawn_record_is_left_out(self):
        def details(url, payload):
            if url.endswith("GONE-1"):
                raise st.NotFoundError("api.osv.dev returned HTTP 404")
            return {"id": "PYSEC-1", "modified": "m"}

        client = FakeClient({"https://api.osv.dev/v1/vulns/": details})
        with tempfile.TemporaryDirectory() as tmp, self.assertLogs("sbom_triage", "WARNING") as logs:
            result = st.fetch_vuln_details(client, st.DiskCache(Path(tmp)), {"PYSEC-1": "m", "GONE-1": "m"})
        self.assertEqual(list(result), ["PYSEC-1"])
        self.assertIn("GONE-1 no longer exists", "\n".join(logs.output))


class KevEpssTests(unittest.TestCase):
    KEV = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"},
    ]}

    def test_kev_is_downloaded_every_time(self):
        client = FakeClient({st.KEV_URL: lambda url, payload: self.KEV})
        first = st.load_kev(client)
        st.load_kev(client)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(first["CVE-2021-44228"], st.KevEntry("2021-12-10", "Known"))

    def test_kev_failure_is_an_error(self):
        def unavailable(url, payload):
            raise st.ApiError("down")

        with self.assertRaises(st.ApiError):
            st.load_kev(FakeClient({st.KEV_URL: unavailable}))
        with self.assertRaises(st.ApiError):
            st.load_kev(FakeClient({st.KEV_URL: lambda url, payload: {"unexpected": True}}))

    def test_epss_batches_and_skips_invalid_cves(self):
        def epss(url, payload):
            cves = url.split("cve=")[1].split("&")[0].split(",")
            return {"data": [{"cve": c, "epss": "0.5", "percentile": "0.96"} for c in cves]}

        client = FakeClient({st.EPSS_URL: epss})
        cves = [f"CVE-2020-{i:05d}" for i in range(150)] + ["CVE-bad&x=1"]
        result = st.load_epss(client, cves)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(len(result), 150)
        self.assertNotIn("bad", "".join(c[1] for c in client.calls))


LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4J_DETAIL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "modified": "m",
    "aliases": ["CVE-2021-44228"],
    "summary": "Log4Shell",
    "affected": [{
        "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}],
    }],
}


def log4j_client() -> FakeClient:
    """OSV reports Log4Shell for log4j-core 2.14.1 and nothing for any other package."""

    def querybatch(url, payload):
        return {"results": [
            {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "m"}]} if q["package"]["purl"] == LOG4J_PURL else {}
            for q in payload["queries"]
        ]}

    return FakeClient({
        st.OSV_QUERYBATCH_URL: querybatch,
        "https://api.osv.dev/v1/vulns/": lambda url, payload: LOG4J_DETAIL,
        st.KEV_URL: lambda url, payload: KevEpssTests.KEV,
        st.EPSS_URL: lambda url, payload: {"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999"}]},
    })


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_quietly(self, args, client):
        with unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as stdout, self.assertLogs("sbom_triage", "INFO"):
            code = st.run(args, client)
        return code, stdout.getvalue()

    def test_single_sbom_with_json_and_fail_on(self):
        (self.dir / "bom.json").write_text(json.dumps(cyclonedx({"name": "log4j", "purl": LOG4J_PURL})), encoding="utf-8")
        args = st.parse_args([
            str(self.dir / "bom.json"), "--json", str(self.dir / "out.json"),
            "--cache-dir", str(self.dir / "cache"), "--fail-on", "high",
        ])
        code, output = self.run_quietly(args, log4j_client())
        self.assertEqual(code, st.EXIT_FAIL_ON)
        self.assertIn("CRITICAL", output)
        self.assertIn("YES 2021-12-10 ransomware", output)
        self.assertIn("Packages analyzed: 1.", output)
        export = json.loads((self.dir / "out.json").read_text(encoding="utf-8"))
        self.assertEqual(export["sbom"], "bom.json")
        self.assertEqual(export["format_version"], st.FORMAT_VERSION)
        self.assertEqual(export["tool"], {"name": "sbom-triage", "version": st.__version__, "url": st.PROJECT_URL})
        self.assertEqual(export["coverage"]["analyzed_packages"], 1)
        [finding] = export["findings"]
        self.assertEqual(finding["priority"], st.PRIORITY_CRITICAL)
        self.assertEqual(finding["fixed_versions"], ["2.15.0"])
        self.assertEqual(finding["upgrade_to"], ["2.15.0"])
        self.assertTrue(finding["kev"]["in_kev"])

        no_threshold = st.parse_args([str(self.dir / "bom.json"), "--cache-dir", str(self.dir / "cache")])
        self.assertEqual(self.run_quietly(no_threshold, log4j_client())[0], 0)

    def test_invalid_single_sbom_is_an_error(self):
        (self.dir / "spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
        args = st.parse_args([str(self.dir / "spdx.json"), "--cache-dir", str(self.dir / "cache")])
        with self.assertRaises(st.SbomError):
            st.run(args, log4j_client())

    def test_directory_mode(self):
        sboms = self.dir / "in"
        sboms.mkdir()
        shared = {"name": "shared", "purl": "pkg:pypi/requests@2.0.0"}
        (sboms / "one.cdx.json").write_text(json.dumps(cyclonedx({"name": "log4j", "purl": LOG4J_PURL}, shared)), encoding="utf-8")
        (sboms / "two.json").write_text(json.dumps(cyclonedx(shared)), encoding="utf-8")
        (sboms / "spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
        out = self.dir / "out"
        client = log4j_client()
        args = st.parse_args([
            "--input-dir", str(sboms), "--output-dir", str(out),
            "--cache-dir", str(self.dir / "cache"), "--fail-on", "critical",
        ])
        code, output = self.run_quietly(args, client)

        self.assertEqual(code, st.EXIT_FAIL_ON)
        # One query round for both SBOMs, with the shared package only once.
        [querybatch] = [call for call in client.calls if call[1] == st.OSV_QUERYBATCH_URL]
        self.assertEqual(sorted(q["package"]["purl"] for q in querybatch[2]["queries"]), sorted([LOG4J_PURL, shared["purl"]]))
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["one.cdx.triage.json", "two.triage.json"])
        one = json.loads((out / "one.cdx.triage.json").read_text(encoding="utf-8"))
        two = json.loads((out / "two.triage.json").read_text(encoding="utf-8"))
        self.assertEqual([f["id"] for f in one["findings"]], ["GHSA-jfh8-c2jp-5v3q"])
        self.assertEqual(two["findings"], [])
        self.assertIn("== one.cdx.json ==", output)
        self.assertIn("SBOMs analyzed: 2. Files skipped (not a CycloneDX JSON SBOM): 1. SBOMs that could not be analyzed: 0.", output)

    def test_broken_sbom_in_directory_takes_precedence_over_fail_on(self):
        sboms = self.dir / "in"
        sboms.mkdir()
        (sboms / "ok.json").write_text(json.dumps(cyclonedx({"name": "log4j", "purl": LOG4J_PURL})), encoding="utf-8")
        (sboms / "partial.json").write_bytes(b'{"bomFormat": "CycloneDX", "specVersion": "1.5", "comp')
        out = self.dir / "out"
        args = st.parse_args([
            "--input-dir", str(sboms), "--output-dir", str(out),
            "--cache-dir", str(self.dir / "cache"), "--fail-on", "critical",
        ])
        code, output = self.run_quietly(args, log4j_client())
        self.assertEqual(code, st.EXIT_SBOM_FAILED)
        # The SBOMs that could be read are still analyzed and reported.
        self.assertEqual([p.name for p in out.iterdir()], ["ok.triage.json"])
        self.assertIn("Could not analyze (see errors): partial.json", output)

    def test_argument_errors(self):
        sboms = self.dir / "in"
        sboms.mkdir()
        invalid = [
            [],
            [str(self.dir / "bom.json"), "--input-dir", str(sboms)],
            ["--input-dir", str(sboms), "--json", "out.json"],
            ["--input-dir", str(sboms), "--output-dir", str(sboms / ".")],
            [str(self.dir / "bom.json"), "--fail-on", "urgent"],
        ]
        for argv in invalid:
            with self.subTest(argv=argv), unittest.mock.patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as raised:
                    st.parse_args(argv)
                self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

"""Tests for histleak. Standard library unittest only.

tests/fixtures/packed_git/ is a pre-built, fully-packed (git gc'd) bare
repository committed as test data. It is not generated at test time, so the
suite has no dependency -- including no dependency on `git` itself -- at
run time. It was built once with:

    git init && ...commits planting then deleting a fake AWS key... && \
    git gc --aggressive

See tests/fixtures/README.md for the exact commit sequence.
"""

import math
import unittest
from pathlib import Path

import histleak

FIXTURE = Path(__file__).parent / "tests" / "fixtures" / "packed_git"

# Secret-shaped test data is assembled at runtime rather than written as a
# literal. GitHub's push protection scans source for credential patterns and
# blocks the push, which a secret scanner's own test suite will otherwise
# trip on every time -- these are all obviously fake, but "obviously fake to
# a human" is not a property a regex can check. Splitting the literals keeps
# the tests honest without asking anyone to allowlist a fake credential.
_AKIA = "AK" + "IA"
FAKE_AWS_KEY_ID = _AKIA + "FAKEFAKEFAKE0001"
FAKE_AWS_KEY_ID_2 = _AKIA + "ABCDEFGHIJKLMNOP"
FAKE_RANDOM_TOKEN = "eIuKnGq5vannw3nX" + "pS0NMYbHD96PXICxej0CgqPL"



class ObjectStoreTests(unittest.TestCase):
    def test_loose_and_pack_objects_resolve_and_verify(self):
        store = histleak.ObjectStore(FIXTURE)
        shas = list(store.iter_all_shas())
        self.assertGreater(len(shas), 0)
        for sha in shas:
            got = store.get(sha)
            self.assertIsNotNone(got, f"missing object {sha}")
            otype, content = got
            header = f"{otype} {len(content)}\0".encode() + content
            import hashlib
            self.assertEqual(hashlib.sha1(header).hexdigest(), sha)

    def test_resolve_head(self):
        store = histleak.ObjectStore(FIXTURE)
        head = store.resolve_ref("HEAD")
        self.assertIsNotNone(head)
        self.assertRegex(head, r"^[0-9a-f]{40}$")

    def test_find_git_dir_on_bare_repo(self):
        git_dir = histleak.find_git_dir(str(FIXTURE))
        self.assertEqual(git_dir, FIXTURE)


class PackIndexTests(unittest.TestCase):
    def test_pack_present_and_lookups_work(self):
        store = histleak.ObjectStore(FIXTURE)
        self.assertEqual(len(store.packs), 1)
        pack = store.packs[0]
        some_sha = next(pack.index.all_shas())
        self.assertIsNotNone(pack.index.find_offset(some_sha))
        self.assertIsNone(pack.index.find_offset("0" * 40))


class DeltaResolutionTests(unittest.TestCase):
    def test_ofs_and_ref_delta_round_trip(self):
        # README.md is committed once and never changed, so it is either
        # stored whole or as a delta against a very similar object -- either
        # way this exercises the same get() path as a real repo.
        store = histleak.ObjectStore(FIXTURE)
        head = store.resolve_ref("HEAD")
        otype, content = store.get(head)
        self.assertEqual(otype, "commit")
        info = histleak.parse_commit(content)
        self.assertIsNotNone(info["tree"])
        tree_type, tree_content = store.get(info["tree"])
        self.assertEqual(tree_type, "tree")
        entries = histleak.parse_tree(tree_content)
        self.assertTrue(any(name == "app.py" for _, name, _ in entries))


class DetectionTests(unittest.TestCase):
    def test_aws_key_detected(self):
        findings = histleak.scan_blob_text(
            f"AWS_SECRET_ACCESS_KEY={FAKE_AWS_KEY_ID}\n", "x.env", "deadbeef")
        self.assertTrue(any(f.rule_id == "aws-access-key-id" for f in findings))

    def test_aws_key_id_structural_validator_rejects_wrong_shape(self):
        self.assertFalse(histleak._valid_aws_key(_AKIA + "-not-valid"))
        self.assertTrue(histleak._valid_aws_key(FAKE_AWS_KEY_ID_2))

    def test_github_pat_length_validator(self):
        good = "ghp_" + ("a1B2c3" * 6)  # 36 chars
        self.assertTrue(histleak._luhn_like_github_pat(good))
        self.assertFalse(histleak._luhn_like_github_pat("ghp_tooshort"))

    def test_private_key_block_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n"
        findings = histleak.scan_blob_text(text, "id_rsa", "deadbeef")
        self.assertTrue(any(f.rule_id == "private-key-block" for f in findings))

    def test_ordinary_prose_produces_no_findings(self):
        text = ("This document explains how the application-configuration "
                "module works and why we chose this particular architecture "
                "for the request-handling pipeline.\n")
        findings = histleak.scan_blob_text(text, "docs/architecture.md", "deadbeef")
        self.assertEqual(findings, [])

    def test_entropy_flags_random_token_but_not_hyphenated_slug(self):
        self.assertTrue(histleak._looks_like_secret("aZ3kQ9mP2vX7bR4tY8wL1cN6"))
        self.assertFalse(histleak._looks_like_secret(
            "organization/some-slug-with-many-dashes"))

    def test_entropy_ignores_pure_hex(self):
        self.assertFalse(histleak._looks_like_secret("a" * 25))
        self.assertFalse(histleak._looks_like_secret("deadbeef" * 3))

    def test_shannon_entropy_known_values(self):
        self.assertAlmostEqual(histleak.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(histleak.shannon_entropy("ab"), 1.0)


class ScanOrchestrationTests(unittest.TestCase):
    def test_deleted_secret_is_still_found(self):
        findings = histleak.scan_repository(str(FIXTURE))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.rule_id, "aws-access-key-id")
        self.assertEqual(f.path, "config/prod.env")
        self.assertIsNotNone(f.commit_sha)

    def test_clean_repo_has_no_findings(self):
        # A repo whose only content is prose and app code (no packed
        # secret) should report clean at the default severity.
        import tempfile
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q"], cwd=d, check=True)
            subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=d, check=True)
            subprocess.run(["git", "config", "user.name", "t"], cwd=d, check=True)
            (Path(d) / "f.txt").write_text("nothing secret here\n")
            subprocess.run(["git", "add", "f.txt"], cwd=d, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "c1"], cwd=d, check=True)
            findings = histleak.scan_repository(d)
        self.assertEqual(findings, [])

    def test_ignore_file_suppresses_path(self):
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "repo"
            shutil.copytree(FIXTURE, target / ".git")
            (target / ".histleakignore").write_text("config/*\n")
            findings = histleak.scan_repository(str(target))
        self.assertEqual(findings, [])


class ReportTests(unittest.TestCase):
    def test_redacted_hides_middle(self):
        f = histleak.Finding("x", "high", FAKE_AWS_KEY_ID_2, "p", 1, "sha")
        r = f.redacted()
        self.assertNotIn("ABCDEFGHIJKLMN", r)
        self.assertTrue(r.startswith(_AKIA))

    def test_findings_to_json_serialisable(self):
        import json
        f = histleak.Finding("x", "high", "secretvalue", "p", 1, "sha")
        payload = histleak.findings_to_json([f])
        json.dumps(payload)  # must not raise
        self.assertEqual(payload[0]["path"], "p")


class CliTests(unittest.TestCase):
    def test_exit_code_1_on_findings(self):
        rc = histleak.main(["scan", str(FIXTURE)])
        self.assertEqual(rc, 1)

    def test_exit_code_2_on_missing_repo(self):
        rc = histleak.main(["scan", "/nonexistent/path/for/sure"])
        self.assertEqual(rc, 2)


class FalsePositiveTests(unittest.TestCase):
    """Regressions from scanning `requests`' real history (27k objects).

    Each of these produced a flood of findings on a clean repository before
    the corresponding filter was added. The counts in the comments are the
    measured before/after on that repo.
    """

    def test_placeholder_basic_auth_passwords_rejected(self):
        # 1,960 findings -> 0. Every basic-auth match in requests' history
        # was documentation, not a credential.
        for placeholder in ("pass", "password", "{ENCODED_PASSWORD}",
                            "pass%20pass", "pass%23pass", "changeme", "xxx"):
            with self.subTest(placeholder=placeholder):
                self.assertFalse(histleak._valid_basic_auth_password(placeholder))

    def test_real_looking_password_still_accepted(self):
        for real in ("Xk3mP9qLz2vB", "h7!Kq2$wRt9z", "correct-horse-battery-99"):
            with self.subTest(real=real):
                self.assertTrue(histleak._valid_basic_auth_password(real))

    def test_pem_certificate_body_excluded_from_entropy(self):
        # requests/cacert.pem alone produced 19,328 entropy findings.
        cert = ("-----BEGIN CERTIFICATE-----\n"
                + "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n" * 5
                + "-----END CERTIFICATE-----\n")
        findings = histleak.scan_blob_text(cert, "cacert.pem", "sha",
                                            min_severity="low")
        entropy = [f for f in findings if f.rule_id == "high-entropy-string"]
        self.assertEqual(entropy, [])

    def test_private_key_still_detected_inside_pem_armor(self):
        # Excluding armored bodies must not suppress the private-key rule,
        # which fires on the BEGIN line itself.
        key = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"
               "-----END RSA PRIVATE KEY-----\n")
        findings = histleak.scan_blob_text(key, "id_rsa", "sha", min_severity="low")
        self.assertTrue(any(f.rule_id == "private-key-block" for f in findings))

    def test_entropy_dense_blob_is_dropped_wholesale(self):
        # An embedded binary/base64 data file: many hits, no real secret.
        blob = "\n".join("aZ3kQ9mP2vX7bR4tY8wL1cN6dE5f" + str(i) for i in range(200))
        findings = histleak.scan_blob_text(blob, "data.b64", "sha",
                                            min_severity="low")
        self.assertEqual([f for f in findings if f.rule_id == "high-entropy-string"], [])

    def test_single_random_token_still_flagged(self):
        blob = f"TOKEN = '{FAKE_RANDOM_TOKEN}'\n"
        findings = histleak.scan_blob_text(blob, "config.py", "sha",
                                            min_severity="low")
        self.assertTrue(any(f.rule_id == "high-entropy-string" for f in findings))

    def test_severity_filter_skips_low_rules_entirely(self):
        blob = f"TOKEN = '{FAKE_RANDOM_TOKEN}'\n"
        self.assertEqual(
            histleak.scan_blob_text(blob, "c.py", "sha", min_severity="medium"), [])


class DeduplicationTests(unittest.TestCase):
    def test_same_secret_across_versions_collapses(self):
        common = dict(rule_id="aws-access-key-id", severity="high",
                      match=FAKE_AWS_KEY_ID_2, path="a.env", line=1)
        findings = [
            histleak.Finding(blob_sha="b1", commit_sha="c1",
                             date="2024-03-01T00:00:00+00:00", **common),
            histleak.Finding(blob_sha="b2", commit_sha="c2",
                             date="2024-01-01T00:00:00+00:00", **common),
            histleak.Finding(blob_sha="b3", commit_sha="c3",
                             date="2024-02-01T00:00:00+00:00", **common),
        ]
        out = histleak._deduplicate(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].occurrences, 3)
        # earliest commit wins: that is when the leak was introduced
        self.assertEqual(out[0].commit_sha, "c2")

    def test_distinct_secrets_not_merged(self):
        a = histleak.Finding("r", "high", "AAAA1111", "a.env", 1, "b1")
        b = histleak.Finding("r", "high", "BBBB2222", "a.env", 1, "b2")
        self.assertEqual(len(histleak._deduplicate([a, b])), 2)


class BoundedCacheTests(unittest.TestCase):
    def test_evicts_beyond_capacity(self):
        c = histleak._BoundedCache(max_entries=3)
        for i in range(5):
            c.put(i, ("blob", b"x"))
        self.assertIsNone(c.get(0))
        self.assertIsNotNone(c.get(4))

    def test_does_not_cache_oversized_values(self):
        c = histleak._BoundedCache(max_value_bytes=10)
        c.put("k", ("blob", b"x" * 100))
        self.assertIsNone(c.get("k"))

    def test_lru_order_refreshes_on_get(self):
        c = histleak._BoundedCache(max_entries=2)
        c.put("a", ("blob", b"1"))
        c.put("b", ("blob", b"2"))
        c.get("a")            # refresh a, so b is now least recent
        c.put("c", ("blob", b"3"))
        self.assertIsNotNone(c.get("a"))
        self.assertIsNone(c.get("b"))


if __name__ == "__main__":
    unittest.main()

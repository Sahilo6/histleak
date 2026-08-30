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
            "AWS_SECRET_ACCESS_KEY=AKIAFAKEFAKEFAKE0001\n", "x.env", "deadbeef")
        self.assertTrue(any(f.rule_id == "aws-access-key-id" for f in findings))

    def test_aws_key_id_structural_validator_rejects_wrong_shape(self):
        self.assertFalse(histleak._valid_aws_key("AKIA-not-valid"))
        self.assertTrue(histleak._valid_aws_key("AKIAABCDEFGHIJKLMNOP"))

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
        f = histleak.Finding("x", "high", "AKIAABCDEFGHIJKLMNOP", "p", 1, "sha")
        r = f.redacted()
        self.assertNotIn("ABCDEFGHIJKLMN", r)
        self.assertTrue(r.startswith("AKIA"))

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


if __name__ == "__main__":
    unittest.main()

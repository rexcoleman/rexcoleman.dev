from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.ci_exact_commit_integrity import Refusal, verify


def run(root: Path, *args: str) -> str:
    result = subprocess.run(
        list(args), cwd=root, text=True, capture_output=True, check=True
    )
    return result.stdout


class ExactCommitIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="exact-commit-integrity-")
        self.root = Path(self.temp.name)
        run(self.root, "git", "init", "-q")
        run(self.root, "git", "config", "user.name", "Integrity Test")
        run(self.root, "git", "config", "user.email", "integrity@example.invalid")
        workflow = self.root / ".github" / "workflows" / "artifact-integrity.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: artifact-integrity\n", encoding="utf-8")
        (self.root / "README.md").write_text("faithful\n", encoding="utf-8")
        run(self.root, "git", "add", ".")
        run(self.root, "git", "commit", "-q", "-m", "faithful")
        self.head = run(self.root, "git", "rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def commit_handoff(self, body: str, rows: list[dict[str, object]]) -> str:
        handoff = self.root / "outputs" / "TEST_HANDOFF.md"
        handoff.parent.mkdir(parents=True, exist_ok=True)
        handoff.write_text(body, encoding="utf-8")
        sidecar = handoff.with_name(handoff.name + ".prose-bindings.json")
        sidecar.write_text(
            json.dumps(
                {
                    "document": "outputs/TEST_HANDOFF.md",
                    "schema_version": "rea.prose-artifact-bindings.v1",
                    "tokens": rows,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        run(self.root, "git", "add", "outputs")
        run(self.root, "git", "commit", "-q", "-m", "handoff")
        return run(self.root, "git", "rev-parse", "HEAD").strip()

    def test_faithful_exact_commit_passes(self) -> None:
        result = verify(self.root, self.head)
        self.assertTrue(result["authorized"])
        self.assertEqual(result["raw_exit"], 0)
        self.assertEqual(result["exact_head"], self.head)

    def test_substituted_expected_head_refuses(self) -> None:
        with self.assertRaises(Refusal) as caught:
            verify(self.root, "0" * 40)
        self.assertEqual(caught.exception.reason, "EXPECTED_HEAD_MISMATCH")

    def test_dirty_checkout_refuses(self) -> None:
        (self.root / "README.md").write_text("planted\n", encoding="utf-8")
        with self.assertRaises(Refusal) as caught:
            verify(self.root, self.head)
        self.assertEqual(caught.exception.reason, "EXACT_CHECKOUT_DIRTY")

    def test_path_bound_digest_and_explicit_foreign_citation_pass(self) -> None:
        artifact = self.root / "artifact.txt"
        artifact.write_text("bound artifact\n", encoding="utf-8")
        run(self.root, "git", "add", "artifact.txt")
        run(self.root, "git", "commit", "-q", "-m", "artifact")
        local_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        local_commit = run(self.root, "git", "rev-parse", "HEAD").strip()
        foreign = "a" * 40
        head = self.commit_handoff(
            f"local {local_sha}\nlocal commit {local_commit}\nforeign {foreign}\n",
            [
                {
                    "binding_kind": "path-sha256",
                    "bucket": "repo-local-artifact-binding",
                    "occurrences": 1,
                    "path": "artifact.txt",
                    "token": local_sha,
                },
                {
                    "binding_kind": "git-commit",
                    "bucket": "repo-local-artifact-binding",
                    "occurrences": 1,
                    "repository": "rexcoleman.dev",
                    "token": local_commit,
                },
                {
                    "binding_kind": "git-commit",
                    "bucket": "foreign-object-citation",
                    "occurrences": 1,
                    "repository": "govML",
                    "token": foreign,
                },
            ],
        )
        result = verify(self.root, head)
        self.assertEqual(result["prose_bindings"]["local_binding_count"], 2)
        self.assertEqual(result["prose_bindings"]["foreign_citation_count"], 1)

    def test_prefix_correct_invented_local_digest_refuses(self) -> None:
        artifact = self.root / "artifact.txt"
        artifact.write_text("bound artifact\n", encoding="utf-8")
        run(self.root, "git", "add", "artifact.txt")
        run(self.root, "git", "commit", "-q", "-m", "artifact")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        invented = actual[:16] + ("0" * 48)
        head = self.commit_handoff(
            f"local {invented}\n",
            [
                {
                    "binding_kind": "path-sha256",
                    "bucket": "repo-local-artifact-binding",
                    "occurrences": 1,
                    "path": "artifact.txt",
                    "token": invented,
                }
            ],
        )
        with self.assertRaises(Refusal) as caught:
            verify(self.root, head)
        self.assertEqual(caught.exception.reason, "PROSE_LOCAL_DIGEST_MISMATCH")
        self.assertEqual(caught.exception.detail["observed"], actual)

    def test_unclassified_bare_hash_refuses(self) -> None:
        token = "b" * 64
        head = self.commit_handoff(f"unclassified {token}\n", [])
        with self.assertRaises(Refusal) as caught:
            verify(self.root, head)
        self.assertEqual(
            caught.exception.reason, "PROSE_HASH_TOKEN_CLASSIFICATION_INCOMPLETE"
        )

    def test_depth_one_checkout_refuses_without_changeset_parent(self) -> None:
        (self.root / "second.txt").write_text("second\n", encoding="utf-8")
        run(self.root, "git", "add", "second.txt")
        run(self.root, "git", "commit", "-q", "-m", "second")
        with tempfile.TemporaryDirectory(prefix="exact-commit-shallow-") as raw:
            shallow = Path(raw) / "repo"
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", self.root.as_uri(), str(shallow)],
                check=True,
            )
            head = run(shallow, "git", "rev-parse", "HEAD").strip()
            with self.assertRaises(Refusal) as caught:
                verify(shallow, head)
            self.assertEqual(caught.exception.reason, "CHANGESET_PARENT_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()

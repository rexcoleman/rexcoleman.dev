from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / ".github/research-integrity/verify_sealed_authority.py"
MANIFEST = ROOT / ".rea/hosted-authority/frozen-manifest.json"
ORIGIN = "https://github.com/rexcoleman/rexcoleman.dev"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


def commit_repo(root: Path, message: str) -> str:
    git(root, "add", ".")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


class HostedAuthorityVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.target = self.base / "target"
        self.control = self.base / "control"
        self.target.mkdir()
        self.control.mkdir()
        for repo in (self.target, self.control):
            git(repo, "init")
            git(repo, "checkout", "-b", "main")
            git(repo, "config", "user.name", "Item F Test")
            git(repo, "config", "user.email", "item-f@example.invalid")
        git(self.target, "remote", "add", "origin", ORIGIN)

        seal = self.target / ".rea/hosted-authority/authority-seal.json"
        mount = self.target / "scripts/blog_publish_mount.py"
        publish = self.target / "publish.sh"
        candidate_verifier = self.target / ".github/research-integrity/verify_sealed_authority.py"
        seal.parent.mkdir(parents=True)
        mount.parent.mkdir(parents=True)
        candidate_verifier.parent.mkdir(parents=True)
        seal.write_text(
            json.dumps(
                {
                    "schema_version": "rea.hosted-authority-seal.v1",
                    "seal_id": "a361ee29dcffa43bf9bfe901f01d304b",
                    "state": "SEALED",
                    "routes": ["BLG-09", "BLG-10"],
                    "verification_scope": "EXACT_PUSHED_SHA_TRANSPORT_ONLY",
                    "semantic_authorization": False,
                    "deployment_authorization": False,
                },
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        mount.write_bytes(b"public mount bytes\n")
        publish.write_bytes(b"public publish bytes\n")
        candidate_verifier.write_text(
            "from pathlib import Path\nPath('CANDIDATE_EXECUTED').write_text('bad')\n",
            encoding="utf-8",
        )
        self.faithful_sha = commit_repo(self.target, "faithful target")

        control_verifier = self.control / ".github/research-integrity/verify_sealed_authority.py"
        control_manifest = self.control / ".rea/hosted-authority/frozen-manifest.json"
        control_verifier.parent.mkdir(parents=True)
        control_manifest.parent.mkdir(parents=True)
        shutil.copy2(VERIFIER, control_verifier)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["baseline_target_sha"] = self.faithful_sha
        manifest["target_members"] = [
            {"path": ".rea/hosted-authority/authority-seal.json", "byte_length": seal.stat().st_size, "sha256": sha256(seal)},
            {"path": "scripts/blog_publish_mount.py", "byte_length": mount.stat().st_size, "sha256": sha256(mount)},
            {"path": "publish.sh", "byte_length": publish.stat().st_size, "sha256": sha256(publish)},
        ]
        manifest["control_members"] = [
            {
                "path": ".github/research-integrity/verify_sealed_authority.py",
                "byte_length": control_verifier.stat().st_size,
                "sha256": sha256(control_verifier),
            }
        ]
        control_manifest.write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        self.control_sha = commit_repo(self.control, "frozen control")
        self.control_verifier = control_verifier
        self.control_manifest = control_manifest

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_verifier(self, target_sha: str, expected_sha: str, receipt_name: str) -> tuple[subprocess.CompletedProcess[str], dict]:
        receipt = self.base / receipt_name
        result = subprocess.run(
            [
                sys.executable, "-I", str(self.control_verifier),
                "--manifest", str(self.control_manifest),
                "--control-root", str(self.control),
                "--control-sha", self.control_sha,
                "--target-root", str(self.target),
                "--target-sha", target_sha,
                "--expected-sha", expected_sha,
                "--receipt", str(receipt),
            ],
            text=True, capture_output=True,
        )
        return result, json.loads(receipt.read_text(encoding="utf-8"))

    def test_faithful_exact_sha_verifies_without_candidate_execution(self) -> None:
        result, receipt = self.run_verifier(self.faithful_sha, self.faithful_sha, "faithful.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((receipt["verdict"], receipt["reason_code"]), ("VERIFY", "VERIFIED"))
        self.assertFalse((self.target / "CANDIDATE_EXECUTED").exists())
        self.assertFalse(receipt["semantic_authorization"])
        self.assertFalse(receipt["deployment_authorization"])

    def test_one_committed_authority_byte_tamper_refuses(self) -> None:
        seal = self.target / ".rea/hosted-authority/authority-seal.json"
        raw = bytearray(seal.read_bytes())
        raw[20] ^= 1
        seal.write_bytes(raw)
        tampered_sha = commit_repo(self.target, "one authority byte tampered")
        result, receipt = self.run_verifier(tampered_sha, tampered_sha, "tampered.json")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(receipt["verdict"], "REFUSE")
        self.assertIn(receipt["reason_code"], {"SEALED_AUTHORITY_LENGTH_MISMATCH", "SEALED_AUTHORITY_DIGEST_MISMATCH"})

    def test_valid_checkout_with_wrong_expected_sha_refuses(self) -> None:
        (self.target / "wrong-expected-marker.txt").write_text("committed\n", encoding="utf-8")
        wrong = commit_repo(self.target, "valid but wrong expected SHA")
        git(self.target, "checkout", "--detach", self.faithful_sha)
        result, receipt = self.run_verifier(self.faithful_sha, wrong, "wrong-sha.json")
        self.assertEqual(result.returncode, 3)
        self.assertEqual((receipt["verdict"], receipt["reason_code"]), ("REFUSE", "TARGET_SHA_MISMATCH"))

    def test_unlisted_change_cannot_mint_a_new_sealed_target(self) -> None:
        (self.target / "unlisted.txt").write_text("does not change sealed members\n", encoding="utf-8")
        unsealed_sha = commit_repo(self.target, "unlisted change")
        result, receipt = self.run_verifier(unsealed_sha, unsealed_sha, "unsealed-sha.json")
        self.assertEqual(result.returncode, 3)
        self.assertEqual((receipt["verdict"], receipt["reason_code"]), ("REFUSE", "TARGET_NOT_SEALED_SHA"))

    def test_manifest_is_transport_only_and_deploy_has_no_push_trigger(self) -> None:
        raw = MANIFEST.read_text(encoding="utf-8")
        value = json.loads(raw)
        self.assertFalse(value["semantic_authorization"])
        self.assertFalse(value["deployment_authorization"])
        self.assertFalse(value["private_authority_material_included"])
        self.assertNotIn("findings_sha256", raw.casefold())
        workflow = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
        trigger_block = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger_block)
        self.assertNotIn("push:", trigger_block)


if __name__ == "__main__":
    unittest.main()

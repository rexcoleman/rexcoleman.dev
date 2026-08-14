#!/usr/bin/env python3
"""Plan and rehearse a signed enforcement release before any remote mutation.

The accelerator is deliberately deterministic and machine-only.  It performs
the expensive clean-root, hermetic-test, remote-reachability, impact, and
double-build work before a manifest PR, protected review, issuer dispatch, or
owner boundary exists.  It never merges, tags, approves, issues, installs, or
writes a project checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ADAPTER_SCHEMA = "rea.signed-release-convergence-adapter.v1"
DEPENDENT_ADAPTER_SCHEMA = "rea.signed-release-convergence-adapter.v2"
INDEX_SCHEMA = "rea.signed-release-convergence-index.v1"
INVENTORY_SCHEMA = "rea.signed-release-convergence-inventory.v1"
STATE_SCHEMA = "rea.signed-release-convergence-state.v1"
SUMMARY_SCHEMA = "rea.signed-release-convergence-summary.v1"
RECEIPT_SCHEMA = "rea.signed-release-convergence-phase-receipt.v1"
ALLOWED_MODES = frozenset(("plan", "noop-rehearsal"))
PHASES = (
    "roots",
    "impact",
    "hermetic",
    "manifest-a",
    "manifest-b",
    "contract",
    "poststate",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
LOGICAL = re.compile(r"[A-Za-z0-9_.-]+\Z")
DEFAULT_INDEX = Path(__file__).with_name("signed_release_convergence_index.json")


class Refusal(RuntimeError):
    """Typed fail-closed result."""


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise Refusal("NONREGULAR_FILE:%s" % path)
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise Refusal("FILE_READ_REFUSED:%s:%s" % (path, type(exc).__name__))
    identity = lambda row: (
        row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_mode
    )
    if identity(before) != identity(after):
        raise Refusal("FILE_DRIFT:%s" % path)
    return raw


def secure_regular_bytes(path: Path) -> bytes:
    descriptor = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise Refusal("NONREGULAR_FILE:%s" % path)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise Refusal("NONREGULAR_FILE:%s" % path)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read()
            secured = os.fstat(handle.fileno())
        after = path.lstat()
    except OSError as exc:
        raise Refusal("FILE_SECURE_REFUSED:%s:%s" % (path, type(exc).__name__))
    finally:
        if descriptor is not None:
            os.close(descriptor)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(secured):
        raise Refusal("FILE_DRIFT:%s" % path)
    if identity(secured) != identity(after):
        raise Refusal("FILE_DRIFT:%s" % path)
    if stat.S_IMODE(after.st_mode) != 0o600:
        raise Refusal("FILE_MODE_REFUSED:%s" % path)
    return raw


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=".%s." % path.name, dir=str(path.parent)
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def run(argv, cwd=None, env=None, timeout=900):
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=timeout,
    )
    if completed.returncode:
        raise Refusal(
            "COMMAND_REFUSED:exit=%s:subject=%s:stdout_sha256=%s:stderr_sha256=%s"
            % (
                completed.returncode,
                " ".join(str(item) for item in argv[:4]),
                sha256(completed.stdout.encode("utf-8")),
                sha256(completed.stderr.encode("utf-8")),
            )
        )
    return completed


def closed_dict(value, required, subject):
    if not isinstance(value, dict) or set(value) != set(required):
        raise Refusal(
            "%s_FIELDS_REFUSED:missing=%s:extra=%s"
            % (
                subject,
                sorted(set(required) - set(value) if isinstance(value, dict) else required),
                sorted(set(value) - set(required) if isinstance(value, dict) else []),
            )
        )


def safe_relative(value, suffix=None):
    if not isinstance(value, str):
        raise Refusal("RELATIVE_PATH_TYPE_REFUSED")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise Refusal("RELATIVE_PATH_REFUSED:%s" % value)
    if suffix is not None and path.suffix != suffix:
        raise Refusal("RELATIVE_PATH_SUFFIX_REFUSED:%s" % value)
    return path


def load_adapter(path: Path):
    try:
        value = json.loads(regular_bytes(path))
    except ValueError:
        raise Refusal("ADAPTER_JSON_REFUSED")
    required = {
        "schema_version",
        "adapter_id",
        "authority_generation",
        "expected_member_count",
        "manifest_path",
        "manifest_builder",
        "manifest_builder_flag",
        "ruleset_repository",
        "ruleset_id",
        "repositories",
        "hermetic_tests",
        "system_python_sources",
        "boundaries",
    }
    if value.get("schema_version") == DEPENDENT_ADAPTER_SCHEMA:
        required.add("dependent_project")
    closed_dict(value, required, "ADAPTER")
    if value["schema_version"] not in (ADAPTER_SCHEMA, DEPENDENT_ADAPTER_SCHEMA):
        raise Refusal("ADAPTER_SCHEMA_REFUSED")
    if not isinstance(value["adapter_id"], str) or not LOGICAL.fullmatch(
        value["adapter_id"]
    ):
        raise Refusal("ADAPTER_ID_REFUSED")
    if value["authority_generation"] != 5:
        raise Refusal("AUTHORITY_GENERATION_REFUSED")
    if (
        isinstance(value["expected_member_count"], bool)
        or not isinstance(value["expected_member_count"], int)
        or value["expected_member_count"] < 1
    ):
        raise Refusal("EXPECTED_MEMBER_COUNT_REFUSED")
    safe_relative(value["manifest_path"], ".json")
    safe_relative(value["manifest_builder"], ".py")
    if value["manifest_builder_flag"] != "--successor-ci-materialization":
        raise Refusal("MANIFEST_BUILDER_FLAG_REFUSED")
    if not isinstance(value["ruleset_id"], int) or isinstance(
        value["ruleset_id"], bool
    ):
        raise Refusal("RULESET_ID_REFUSED")
    if not isinstance(value["ruleset_repository"], str) or not re.fullmatch(
        r"rexcoleman/[A-Za-z0-9_.-]+", value["ruleset_repository"]
    ):
        raise Refusal("RULESET_REPOSITORY_REFUSED")
    repositories = value["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 5:
        raise Refusal("REPOSITORY_SET_REFUSED")
    logical_names = []
    for row in repositories:
        closed_dict(row, {"logical_name", "slug", "default_branch"}, "REPOSITORY")
        if (
            not isinstance(row["logical_name"], str)
            or not LOGICAL.fullmatch(row["logical_name"])
            or not isinstance(row["slug"], str)
            or not LOGICAL.fullmatch(row["slug"])
            or row["default_branch"] not in ("main", "master")
        ):
            raise Refusal("REPOSITORY_ROW_REFUSED")
        logical_names.append(row["logical_name"])
    expected = {
        "research_enforcement_activation",
        "govML",
        "Moonshots_Career_Thesis_v2",
        "newsletter",
        "rexcoleman.dev",
    }
    if set(logical_names) != expected or len(set(logical_names)) != len(logical_names):
        raise Refusal("REPOSITORY_LOGICAL_NAMES_REFUSED")
    tests = value["hermetic_tests"]
    if not isinstance(tests, list) or not tests:
        raise Refusal("HERMETIC_TESTS_REFUSED")
    known = set(logical_names)
    for row in tests:
        closed_dict(row, {"name", "repository", "paths"}, "HERMETIC_TEST")
        if (
            not isinstance(row["name"], str)
            or not LOGICAL.fullmatch(row["name"])
            or row["repository"] not in known
            or not isinstance(row["paths"], list)
            or not row["paths"]
        ):
            raise Refusal("HERMETIC_TEST_ROW_REFUSED")
        for item in row["paths"]:
            path_item = safe_relative(item, ".py")
            admitted_prefix = (
                path_item.parts[:1] == ("tests",)
                or path_item.parts[:3] == (".github", "write-enforcement", "tests")
            )
            if not admitted_prefix:
                raise Refusal("HERMETIC_TEST_PATH_REFUSED:%s" % item)
    sources = value["system_python_sources"]
    if not isinstance(sources, list) or not sources:
        raise Refusal("SYSTEM_PYTHON_SOURCES_REFUSED")
    for row in sources:
        closed_dict(row, {"repository", "paths"}, "SYSTEM_PYTHON_SOURCE")
        if (
            row["repository"] not in known
            or not isinstance(row["paths"], list)
            or not row["paths"]
        ):
            raise Refusal("SYSTEM_PYTHON_SOURCE_ROW_REFUSED")
        for item in row["paths"]:
            safe_relative(item, ".py")
    boundaries = value["boundaries"]
    closed_dict(
        boundaries,
        {
            "bcs_partition",
            "owner_rail",
            "anti_spin",
            "remote_mutation",
        },
        "BOUNDARIES",
    )
    expected_boundaries = {
        "bcs_partition": "forbidden",
        "owner_rail": "irreducible-human-only",
        "anti_spin": "not-applicable-deterministic",
        "remote_mutation": "forbidden",
    }
    if boundaries != expected_boundaries:
        raise Refusal("BOUNDARIES_REFUSED")
    if value["schema_version"] == DEPENDENT_ADAPTER_SCHEMA:
        dependent = value["dependent_project"]
        closed_dict(
            dependent,
            {
                "project_id",
                "repository",
                "default_branch",
                "runner_path",
                "preflight_arguments",
                "required_source",
                "named_refusal",
            },
            "DEPENDENT_PROJECT",
        )
        project_id = dependent["project_id"]
        if (
            not isinstance(project_id, str)
            or not LOGICAL.fullmatch(project_id)
            or project_id.lower() != project_id
        ):
            raise Refusal("DEPENDENT_PROJECT_ID_REFUSED")
        expected_adapter_id = "%s-generation-%s" % (
            project_id.replace("_", "-"), value["authority_generation"]
        )
        if value["adapter_id"] != expected_adapter_id:
            raise Refusal("DEPENDENT_PROJECT_ADAPTER_ID_REFUSED")
        if dependent["repository"] != "rexcoleman/%s" % project_id:
            raise Refusal("DEPENDENT_PROJECT_REPOSITORY_REFUSED")
        if dependent["default_branch"] not in ("main", "master"):
            raise Refusal("DEPENDENT_PROJECT_DEFAULT_BRANCH_REFUSED")
        if (
            not isinstance(dependent["named_refusal"], str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]*", dependent["named_refusal"])
        ):
            raise Refusal("DEPENDENT_PROJECT_REFUSAL_ID_REFUSED")
        if safe_relative(dependent["runner_path"]) != Path("scripts/run_gates.sh"):
            raise Refusal("DEPENDENT_PROJECT_RUNNER_REFUSED")
        if dependent["preflight_arguments"] != ["--engine-preflight"]:
            raise Refusal("DEPENDENT_PROJECT_PREFLIGHT_REFUSED")
        if dependent["required_source"] != "SIGNED_BUNDLE":
            raise Refusal("DEPENDENT_PROJECT_SOURCE_REFUSED")
    return value


def load_cross_generation_inventory(path: Path):
    try:
        value = json.loads(regular_bytes(path))
    except ValueError:
        raise Refusal("INVENTORY_JSON_REFUSED")
    closed_dict(value, {
        "schema_version", "repositories", "properties",
        "untested_properties", "entries",
    }, "INVENTORY")
    if value["schema_version"] != INVENTORY_SCHEMA:
        raise Refusal("INVENTORY_SCHEMA_REFUSED")
    properties = {"hermetic", "identity", "resume", "refusal", "poststate", "evidence"}
    if set(value["properties"]) != properties or any(
        status not in ("tested", "untested") for status in value["properties"].values()
    ):
        raise Refusal("INVENTORY_PROPERTY_SET_REFUSED")
    expected_untested = sorted(
        name for name, status in value["properties"].items() if status == "untested"
    )
    if value["untested_properties"] != expected_untested:
        raise Refusal("INVENTORY_UNTESTED_PROPERTY_MISMATCH")
    if set(value["repositories"]) != {"govML", "rexcoleman.dev"}:
        raise Refusal("INVENTORY_REPOSITORY_SET_REFUSED")
    for row in value["repositories"].values():
        closed_dict(row, {"default_branch"}, "INVENTORY_REPOSITORY")
        if row["default_branch"] != "main":
            raise Refusal("INVENTORY_DEFAULT_BRANCH_REFUSED")
    identifiers = []
    sessions = set()
    for row in value["entries"]:
        closed_dict(row, {
            "id", "repository", "session", "path", "kind", "markers", "properties",
        }, "INVENTORY_ENTRY")
        if (
            not LOGICAL.fullmatch(row["id"])
            or row["repository"] not in value["repositories"]
            or not re.fullmatch(r"s[0-9]+", row["session"])
            or row["kind"] not in {"adapter", "engine", "evidence-suite", "test"}
        ):
            raise Refusal("INVENTORY_ENTRY_IDENTITY_REFUSED")
        safe_relative(row["path"])
        if (
            not isinstance(row["markers"], list) or not row["markers"]
            or not all(isinstance(marker, str) and marker for marker in row["markers"])
            or not isinstance(row["properties"], list) or not row["properties"]
            or not set(row["properties"]).issubset(properties)
        ):
            raise Refusal("INVENTORY_ENTRY_COVERAGE_REFUSED")
        identifiers.append(row["id"])
        sessions.add(row["session"])
    if len(identifiers) != len(set(identifiers)) or len(sessions) < 6:
        raise Refusal("INVENTORY_BREADTH_REFUSED")
    return value


def load_index(path: Path):
    try:
        value = json.loads(regular_bytes(path))
    except ValueError:
        raise Refusal("INDEX_JSON_REFUSED")
    required = {
        "schema_version",
        "engine",
        "documentation",
        "index_guide",
        "cross_generation_inventory",
        "focused_tests",
        "workflow",
        "adapters",
    }
    closed_dict(value, required, "INDEX")
    if value["schema_version"] != INDEX_SCHEMA:
        raise Refusal("INDEX_SCHEMA_REFUSED")
    paths = {
        "engine": ("signed_release_convergence.py", ".py"),
        "documentation": ("SIGNED_RELEASE_CONVERGENCE.md", ".md"),
        "index_guide": ("SIGNED_RELEASE_CONVERGENCE_INDEX.md", ".md"),
        "cross_generation_inventory": ("signed_release_convergence_inventory.json", ".json"),
        "focused_tests": ("tests/test_signed_release_convergence.py", ".py"),
        "workflow": ("../workflows/signed-release-convergence.yml", ".yml"),
    }
    index_root = path.resolve().parent
    for field, (expected, suffix) in paths.items():
        if not isinstance(value[field], str):
            raise Refusal("INDEX_PATH_TYPE_REFUSED:%s" % field)
        if value[field] != expected:
            raise Refusal("INDEX_PATH_IDENTITY_REFUSED:%s" % field)
        relative = Path(value[field])
        if relative.is_absolute() or not relative.parts or relative.suffix != suffix:
            raise Refusal("INDEX_PATH_REFUSED:%s" % field)
        target = (index_root / relative).resolve()
        try:
            target.relative_to(index_root.parent)
        except ValueError:
            raise Refusal("INDEX_PATH_SCOPE_REFUSED:%s" % field)
        regular_bytes(target)
    load_cross_generation_inventory(
        index_root / value["cross_generation_inventory"]
    )
    rows = value["adapters"]
    if not isinstance(rows, list) or not rows:
        raise Refusal("INDEX_ADAPTERS_REFUSED")
    identifiers = []
    for row in rows:
        closed_dict(row, {"adapter_id", "path", "status"}, "INDEX_ADAPTER")
        if (
            not isinstance(row["adapter_id"], str)
            or not LOGICAL.fullmatch(row["adapter_id"])
            or row["status"] not in ("active", "retired")
        ):
            raise Refusal("INDEX_ADAPTER_ROW_REFUSED")
        relative_adapter = safe_relative(row["path"], ".json")
        if relative_adapter.parts[:1] != ("adapters",):
            raise Refusal("INDEX_ADAPTER_PATH_REFUSED:%s" % row["adapter_id"])
        adapter_path = index_root / relative_adapter
        try:
            adapter_path.resolve().relative_to(index_root)
        except ValueError:
            raise Refusal("INDEX_ADAPTER_PATH_SCOPE_REFUSED")
        adapter = load_adapter(adapter_path)
        if adapter["adapter_id"] != row["adapter_id"]:
            raise Refusal("INDEX_ADAPTER_ID_MISMATCH:%s" % row["adapter_id"])
        identifiers.append(row["adapter_id"])
    if len(set(identifiers)) != len(identifiers):
        raise Refusal("INDEX_ADAPTER_ID_DUPLICATE")
    return value


def resolve_adapter(index_path: Path, adapter_id: str):
    value = load_index(index_path)
    for row in value["adapters"]:
        if row["adapter_id"] != adapter_id:
            continue
        if row["status"] != "active":
            raise Refusal("INDEX_ADAPTER_RETIRED:%s" % adapter_id)
        return index_path.resolve().parent / row["path"]
    raise Refusal("INDEX_ADAPTER_UNKNOWN:%s" % adapter_id)


def parse_roots(rows, adapter):
    parsed = {}
    for row in rows:
        if "=" not in row:
            raise Refusal("ROOT_ARGUMENT_REFUSED")
        logical, raw_path = row.split("=", 1)
        if logical in parsed or not LOGICAL.fullmatch(logical):
            raise Refusal("ROOT_LOGICAL_REFUSED:%s" % logical)
        path = Path(raw_path).resolve()
        if not path.is_dir():
            raise Refusal("ROOT_DIRECTORY_REFUSED:%s" % logical)
        parsed[logical] = path
    expected = {row["logical_name"] for row in adapter["repositories"]}
    if set(parsed) != expected:
        raise Refusal(
            "ROOT_SET_REFUSED:missing=%s:extra=%s"
            % (sorted(expected - set(parsed)), sorted(set(parsed) - expected))
        )
    return parsed


def git(root, *args):
    return run(["git", "-C", str(root)] + list(args), timeout=120).stdout.strip()


def root_snapshot(adapter, roots, baseline):
    expected_commits = {}
    if baseline is not None:
        for row in baseline.get("members", []):
            if not isinstance(row, dict):
                raise Refusal("BASELINE_MEMBER_REFUSED")
            name, commit = row.get("repository"), row.get("commit")
            if name in expected_commits and expected_commits[name] != commit:
                raise Refusal("BASELINE_REPOSITORY_COMMIT_DIVERGENCE:%s" % name)
            expected_commits[name] = commit
    rows = []
    for repository in adapter["repositories"]:
        logical = repository["logical_name"]
        root = roots[logical]
        commit = git(root, "rev-parse", "HEAD")
        if not HEX40.fullmatch(commit):
            raise Refusal("ROOT_HEAD_REFUSED:%s" % logical)
        status = git(root, "status", "--porcelain=v1", "--untracked-files=all")
        if status:
            raise Refusal("ROOT_DIRTY:%s" % logical)
        origin = git(root, "remote", "get-url", "origin")
        accepted = {
            "https://github.com/rexcoleman/%s.git" % repository["slug"],
            "git@github.com:rexcoleman/%s.git" % repository["slug"],
        }
        if origin not in accepted:
            raise Refusal("ROOT_ORIGIN_REFUSED:%s" % logical)
        if baseline is not None and expected_commits.get(logical) != commit:
            raise Refusal(
                "NOOP_ROOT_COMMIT_REFUSED:%s:expected=%s:observed=%s"
                % (logical, expected_commits.get(logical), commit)
            )
        remote = run(
            [
                "gh",
                "api",
                "repos/rexcoleman/%s/commits/%s" % (repository["slug"], commit),
                "--jq",
                ".sha",
            ],
            timeout=60,
        ).stdout.strip()
        if remote != commit:
            raise Refusal("ROOT_REMOTE_REACHABILITY_REFUSED:%s" % logical)
        rows.append(
            {
                "logical_name": logical,
                "slug": repository["slug"],
                "default_branch": repository["default_branch"],
                "commit": commit,
            }
        )
    return rows


def member_contract(rex_root: Path):
    module_path = rex_root / ".github/write-enforcement/member_contract.py"
    namespace = {"__file__": str(module_path), "__name__": "release_member_contract"}
    raw = regular_bytes(module_path)
    exec(compile(raw, str(module_path), "exec"), namespace)
    selector = namespace.get("successor_members")
    if not callable(selector):
        raise Refusal("SUCCESSOR_MEMBER_CONTRACT_SELECTOR_REFUSED")
    try:
        expected = selector()
    except Exception as exc:
        raise Refusal(
            "SUCCESSOR_MEMBER_CONTRACT_REFUSED:%s" % type(exc).__name__
        ) from exc
    if not isinstance(expected, dict):
        raise Refusal("MEMBER_CONTRACT_REFUSED")
    return expected


def impact_snapshot(adapter, roots, root_rows):
    rex_root = roots["rexcoleman.dev"]
    expected = member_contract(rex_root)
    by_subject = {}
    for member_id, subject in expected.items():
        if (
            not isinstance(member_id, str)
            or not isinstance(subject, tuple)
            or len(subject) != 2
        ):
            raise Refusal("MEMBER_CONTRACT_ROW_REFUSED")
        by_subject.setdefault(subject, []).append(member_id)
    result = []
    root_rows_by_name = {row["logical_name"]: row for row in root_rows}
    for repository in adapter["repositories"]:
        logical = repository["logical_name"]
        root = roots[logical]
        head = root_rows_by_name[logical]["commit"]
        base_ref = "refs/remotes/origin/%s" % repository["default_branch"]
        try:
            base = git(root, "rev-parse", base_ref)
        except Refusal:
            raise Refusal("IMPACT_BASE_REF_REFUSED:%s" % logical)
        changed_raw = git(root, "diff", "--name-only", "%s...%s" % (base, head))
        changed = [row for row in changed_raw.splitlines() if row]
        signed = []
        unsigned = []
        for path in changed:
            ids = sorted(by_subject.get((logical, path), []))
            if ids:
                signed.append({"path": path, "member_ids": ids})
            else:
                unsigned.append(path)
        result.append(
            {
                "repository": logical,
                "base": base,
                "head": head,
                "changed_paths": len(changed),
                "signed_changes": signed,
                "unsigned_changes": unsigned,
            }
        )
    return result


def hermetic_environment():
    return {
        "HOME": "/nonexistent/rea-release-preflight",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }


def authenticated_builder_environment():
    """Add only a transient GitHub read token to the minimal build child."""
    token = run(["gh", "auth", "token", "--hostname", "github.com"], timeout=30)
    value = token.stdout.strip()
    if not value or any(char.isspace() for char in value):
        raise Refusal("GITHUB_READ_TOKEN_REFUSED")
    env = hermetic_environment()
    env["GH_TOKEN"] = value
    return env


def pytest_interpreter():
    """Resolve pytest's interpreter before replacing the child environment."""
    candidate = shutil.which("python3")
    if not candidate:
        raise Refusal("PYTEST_PYTHON_ABSENT")
    resolved = Path(candidate).resolve()
    if not resolved.is_file():
        raise Refusal("PYTEST_PYTHON_NONREGULAR")
    try:
        run(
            [str(resolved), "-c", "import pytest"],
            env=hermetic_environment(),
            timeout=30,
        )
    except Refusal as exc:
        raise Refusal("PYTEST_IMPORT_REFUSED:%s" % exc)
    return str(resolved)


def hermetic_snapshot(adapter, roots):
    env = hermetic_environment()
    pytest_python = pytest_interpreter()
    results = []
    compile_program = (
        "import pathlib,sys;"
        "p=pathlib.Path(sys.argv[1]);"
        "compile(p.read_bytes(),str(p),'exec')"
    )
    for row in adapter["system_python_sources"]:
        root = roots[row["repository"]]
        for path in row["paths"]:
            source = root / path
            if not source.is_file():
                raise Refusal("SYSTEM_PYTHON_SOURCE_ABSENT:%s" % path)
            try:
                completed = run(
                    ["/usr/bin/python3", "-c", compile_program, str(source)],
                    cwd=root,
                    env=env,
                    timeout=120,
                )
            except Refusal as exc:
                raise Refusal("SYSTEM_PYTHON_COMPILE_REFUSED:%s:%s" % (path, exc))
            results.append(
                {
                    "name": "system-python-compile",
                    "repository": row["repository"],
                    "path": path,
                    "stdout_sha256": sha256(completed.stdout.encode("utf-8")),
                    "stderr_sha256": sha256(completed.stderr.encode("utf-8")),
                }
            )
    for row in adapter["hermetic_tests"]:
        root = roots[row["repository"]]
        for path in row["paths"]:
            if not (root / path).is_file():
                raise Refusal("HERMETIC_TEST_ABSENT:%s:%s" % (row["name"], path))
        try:
            completed = run(
                [pytest_python, "-m", "pytest", "-q"] + row["paths"],
                cwd=root,
                env=env,
                timeout=1200,
            )
        except Refusal as exc:
            raise Refusal("HERMETIC_TEST_REFUSED:%s:%s" % (row["name"], exc))
        results.append(
            {
                "name": row["name"],
                "repository": row["repository"],
                "paths": row["paths"],
                "stdout_sha256": sha256(completed.stdout.encode("utf-8")),
                "stdout_tail": completed.stdout[-1000:],
                "stderr_sha256": sha256(completed.stderr.encode("utf-8")),
            }
        )
    return results


def ruleset_bytes(adapter):
    completed = run(
        [
            "gh",
            "api",
            "repos/%s/rulesets/%s"
            % (adapter["ruleset_repository"], adapter["ruleset_id"]),
        ],
        timeout=60,
    )
    try:
        value = json.loads(completed.stdout)
    except ValueError:
        raise Refusal("RULESET_JSON_REFUSED")
    if value.get("id") != adapter["ruleset_id"] or value.get("enforcement") != "active":
        raise Refusal("RULESET_IDENTITY_REFUSED")
    return canonical(value) + b"\n"


def builder_argv(adapter, roots, output, ruleset):
    rex = roots["rexcoleman.dev"]
    argv = [
        "/usr/bin/python3",
        str(rex / adapter["manifest_builder"]),
        "--output",
        str(output),
        "--ruleset-json",
        str(ruleset),
        adapter["manifest_builder_flag"],
    ]
    for row in adapter["repositories"]:
        flag = "--root-" + row["logical_name"].lower().replace("_", "-").replace(".", "-")
        argv.extend([flag, str(roots[row["logical_name"]])])
    return argv


def build_manifest(adapter, roots, evidence_dir, label):
    manifest_name = Path(adapter["manifest_path"]).name
    output = evidence_dir / label / manifest_name
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise Refusal("BUILD_OUTPUT_EXISTS:%s" % label)
    ruleset = evidence_dir / "inputs" / "ruleset.json"
    if not ruleset.exists():
        ruleset.parent.mkdir(parents=True, exist_ok=True)
        ruleset.write_bytes(ruleset_bytes(adapter))
        os.chmod(str(ruleset), 0o600)
    completed = run(
        builder_argv(adapter, roots, output, ruleset),
        cwd=roots["rexcoleman.dev"],
        env=authenticated_builder_environment(),
        timeout=1200,
    )
    raw = secure_regular_bytes(output)
    try:
        manifest = json.loads(raw)
    except ValueError:
        raise Refusal("BUILT_MANIFEST_JSON_REFUSED:%s" % label)
    return {
        "label": label,
        "path": str(output),
        "sha256": sha256(raw),
        "byte_length": len(raw),
        "manifest_digest": manifest.get("manifest_digest"),
        "authority_generation": manifest.get("authority_generation"),
        "member_count": len(manifest.get("members", []))
        if isinstance(manifest.get("members"), list)
        else -1,
        "stdout_sha256": sha256(completed.stdout.encode("utf-8")),
        "stderr_sha256": sha256(completed.stderr.encode("utf-8")),
    }


def contract_snapshot(adapter, evidence_dir, mode, baseline):
    a = json.loads(regular_bytes(evidence_dir / "receipts" / "manifest-a.json"))[
        "result"
    ]
    b = json.loads(regular_bytes(evidence_dir / "receipts" / "manifest-b.json"))[
        "result"
    ]
    if a["sha256"] != b["sha256"] or a["manifest_digest"] != b["manifest_digest"]:
        raise Refusal("DETERMINISTIC_REBUILD_REFUSED")
    if (
        a["authority_generation"] != adapter["authority_generation"]
        or a["member_count"] != adapter["expected_member_count"]
        or not HEX64.fullmatch(a["manifest_digest"] or "")
    ):
        raise Refusal("BUILT_MANIFEST_CONTRACT_REFUSED")
    if mode == "noop-rehearsal":
        baseline_raw = regular_bytes(baseline)
        if a["sha256"] != sha256(baseline_raw):
            raise Refusal("NOOP_BASELINE_DIVERGENCE")
    result = {
        "deterministic": True,
        "noop_equal": mode == "noop-rehearsal",
        "manifest_sha256": a["sha256"],
        "manifest_digest": a["manifest_digest"],
        "member_count": a["member_count"],
        "remote_mutation": False,
        "owner_action": False,
        "anti_spin": "not-applicable-deterministic",
        "bcs_surface": "untouched",
    }
    if "dependent_project" in adapter:
        result["dependent_project"] = adapter["dependent_project"]
    return result


def poststate_snapshot(adapter, roots, evidence_dir, baseline):
    baseline_value = json.loads(regular_bytes(baseline)) if baseline else None
    observed = root_snapshot(adapter, roots, baseline_value)
    expected = json.loads(regular_bytes(receipt_path(evidence_dir, "roots")))[
        "result"
    ]
    if canonical(observed) != canonical(expected):
        raise Refusal("ROOT_POSTSTATE_DRIFT")
    return {
        "roots_unchanged": True,
        "remote_mutation": False,
        "root_count": len(observed),
    }


def receipt_path(evidence_dir, phase):
    return evidence_dir / "receipts" / (phase + ".json")


def receipt(evidence_dir, phase, result):
    value = {
        "schema_version": RECEIPT_SCHEMA,
        "phase": phase,
        "result": result,
        "result_sha256": sha256(canonical(result)),
    }
    atomic_json(receipt_path(evidence_dir, phase), value)
    return value


def verify_receipt(evidence_dir, phase, expected_sha):
    path = receipt_path(evidence_dir, phase)
    value = json.loads(regular_bytes(path))
    if (
        value.get("schema_version") != RECEIPT_SCHEMA
        or value.get("phase") != phase
        or value.get("result_sha256") != expected_sha
        or sha256(canonical(value.get("result"))) != expected_sha
    ):
        raise Refusal("PHASE_RECEIPT_DRIFT:%s" % phase)


def new_state(adapter_raw, adapter, mode, evidence_dir, baseline):
    return {
        "schema_version": STATE_SCHEMA,
        "adapter_id": adapter["adapter_id"],
        "adapter_sha256": sha256(adapter_raw),
        "tool_sha256": sha256(regular_bytes(Path(__file__))),
        "mode": mode,
        "baseline_sha256": sha256(regular_bytes(baseline)) if baseline else None,
        "evidence_dir": str(evidence_dir),
        "status": "active",
        "completed": [],
        "receipt_sha256": {},
        "refusal": None,
    }


def load_state(path, adapter_raw, adapter, evidence_dir, baseline):
    try:
        value = json.loads(regular_bytes(path))
    except ValueError:
        raise Refusal("STATE_JSON_REFUSED")
    required = {
        "schema_version",
        "adapter_id",
        "adapter_sha256",
        "tool_sha256",
        "mode",
        "baseline_sha256",
        "evidence_dir",
        "status",
        "completed",
        "receipt_sha256",
        "refusal",
    }
    closed_dict(value, required, "STATE")
    if (
        value["schema_version"] != STATE_SCHEMA
        or value["adapter_id"] != adapter["adapter_id"]
        or value["adapter_sha256"] != sha256(adapter_raw)
        or value["tool_sha256"] != sha256(regular_bytes(Path(__file__)))
        or value["mode"] not in ALLOWED_MODES
        or value["baseline_sha256"]
        != (sha256(regular_bytes(baseline)) if baseline else None)
        or value["evidence_dir"] != str(evidence_dir)
        or not isinstance(value["completed"], list)
        or not isinstance(value["receipt_sha256"], dict)
        or value["completed"] != list(PHASES[: len(value["completed"])])
    ):
        raise Refusal("STATE_IDENTITY_REFUSED")
    for phase in value["completed"]:
        verify_receipt(evidence_dir, phase, value["receipt_sha256"].get(phase))
    value["status"] = "active"
    value["refusal"] = None
    return value


def phase_result(phase, adapter, roots, evidence_dir, mode, baseline):
    if phase == "roots":
        baseline_value = json.loads(regular_bytes(baseline)) if baseline else None
        return root_snapshot(adapter, roots, baseline_value)
    if phase == "impact":
        roots_receipt = json.loads(regular_bytes(receipt_path(evidence_dir, "roots")))
        return impact_snapshot(adapter, roots, roots_receipt["result"])
    if phase == "hermetic":
        return hermetic_snapshot(adapter, roots)
    if phase == "manifest-a":
        return build_manifest(adapter, roots, evidence_dir, "manifest-a")
    if phase == "manifest-b":
        return build_manifest(adapter, roots, evidence_dir, "manifest-b")
    if phase == "contract":
        return contract_snapshot(adapter, evidence_dir, mode, baseline)
    if phase == "poststate":
        return poststate_snapshot(adapter, roots, evidence_dir, baseline)
    raise Refusal("PHASE_UNKNOWN:%s" % phase)


def execute(
    adapter_path,
    state_path,
    evidence_dir,
    roots_raw,
    mode,
    resume,
    baseline_arg=None,
):
    adapter_raw = regular_bytes(adapter_path)
    adapter = load_adapter(adapter_path)
    roots = parse_roots(roots_raw, adapter)
    evidence_dir = evidence_dir.resolve()
    state_path = state_path.resolve()
    baseline = baseline_arg.resolve() if baseline_arg is not None else None
    candidate_mode = mode
    if resume and state_path.exists():
        candidate_mode = json.loads(regular_bytes(state_path)).get("mode")
    if candidate_mode == "noop-rehearsal" and baseline is None:
        raise Refusal("NOOP_BASELINE_REQUIRED")
    if candidate_mode == "plan" and baseline is not None:
        raise Refusal("PLAN_BASELINE_REFUSED")
    if resume:
        if not state_path.exists():
            raise Refusal("STATE_ABSENT")
        state = load_state(
            state_path, adapter_raw, adapter, evidence_dir, baseline
        )
        mode = state["mode"]
        if "roots" in state["completed"]:
            baseline_value = json.loads(regular_bytes(baseline)) if baseline else None
            observed_roots = root_snapshot(adapter, roots, baseline_value)
            prior_roots = json.loads(
                regular_bytes(receipt_path(evidence_dir, "roots"))
            )["result"]
            if canonical(observed_roots) != canonical(prior_roots):
                raise Refusal("RESUME_ROOT_DRIFT")
    else:
        if state_path.exists() or evidence_dir.exists():
            raise Refusal("STATE_OR_EVIDENCE_EXISTS")
        if mode not in ALLOWED_MODES:
            raise Refusal("MODE_REFUSED")
        evidence_dir.mkdir(parents=True, mode=0o700)
        state = new_state(adapter_raw, adapter, mode, evidence_dir, baseline)
        atomic_json(state_path, state)
    try:
        for phase in PHASES[len(state["completed"]) :]:
            result = phase_result(phase, adapter, roots, evidence_dir, mode, baseline)
            value = receipt(evidence_dir, phase, result)
            state["completed"].append(phase)
            state["receipt_sha256"][phase] = value["result_sha256"]
            atomic_json(state_path, state)
        contract = json.loads(regular_bytes(receipt_path(evidence_dir, "contract")))[
            "result"
        ]
        summary = {
            "schema_version": SUMMARY_SCHEMA,
            "adapter_id": adapter["adapter_id"],
            "adapter_sha256": sha256(adapter_raw),
            "tool_sha256": sha256(regular_bytes(Path(__file__))),
            "mode": mode,
            "status": "PASS",
            "phases": list(PHASES),
            "contract": contract,
            "next_remote_step": (
                "none-noop-rehearsal"
                if mode == "noop-rehearsal"
                else "manifest-only-pr-after-independent-review"
            ),
        }
        atomic_json(evidence_dir / "summary.json", summary)
        state["status"] = "complete"
        atomic_json(state_path, state)
        print(
            "SIGNED_RELEASE_CONVERGENCE_PASS adapter=%s mode=%s "
            "manifest_digest=%s member_count=%s remote_mutation=false "
            "owner_action=false"
            % (
                adapter["adapter_id"],
                mode,
                contract["manifest_digest"],
                contract["member_count"],
            )
        )
        return 0
    except Exception as exc:
        state["status"] = "refused"
        state["refusal"] = "%s:%s" % (type(exc).__name__, exc)
        atomic_json(state_path, state)
        raise


def self_test():
    checks = 0
    if canonical({"z": 1, "a": 2}) != b'{"a":2,"z":1}':
        raise AssertionError("canonical JSON")
    checks += 1
    try:
        safe_relative("../escape.py", ".py")
    except Refusal:
        checks += 1
    else:
        raise AssertionError("relative traversal admitted")
    try:
        closed_dict({"a": 1, "extra": 2}, {"a"}, "PLANTED")
    except Refusal:
        checks += 1
    else:
        raise AssertionError("extra adapter field admitted")
    env = hermetic_environment()
    if any(name in env for name in ("GH_TOKEN", "REA_BUNDLE_READ_TOKEN", "SSH_AUTH_SOCK")):
        raise AssertionError("credential inherited")
    checks += 1
    with tempfile.TemporaryDirectory(prefix="release-convergence-self-test-") as raw:
        root = Path(raw)
        target = root / "state.json"
        atomic_json(target, {"ok": True})
        if stat.S_IMODE(target.stat().st_mode) != 0o600:
            raise AssertionError("state mode")
        checks += 1
        evidence = root / "evidence"
        build = {
            "sha256": "a" * 64,
            "manifest_digest": "b" * 64,
            "authority_generation": 5,
            "member_count": 249,
        }
        receipt(evidence, "manifest-a", build)
        receipt(evidence, "manifest-b", build)
        adapter = {"authority_generation": 5, "expected_member_count": 249}
        result = contract_snapshot(adapter, evidence, "plan", None)
        if not result["deterministic"] or result["remote_mutation"]:
            raise AssertionError("deterministic contract")
        checks += 1
        planted = dict(build)
        planted["sha256"] = "c" * 64
        receipt(evidence, "manifest-b", planted)
        try:
            contract_snapshot(adapter, evidence, "plan", None)
        except Refusal as exc:
            if "DETERMINISTIC_REBUILD_REFUSED" not in str(exc):
                raise
            checks += 1
        else:
            raise AssertionError("nondeterminism admitted")
        roots_receipt = receipt(evidence, "roots", [])
        verify_receipt(evidence, "roots", roots_receipt["result_sha256"])
        value = json.loads((evidence / "receipts" / "roots.json").read_text())
        value["result"] = ["tampered"]
        atomic_json(evidence / "receipts" / "roots.json", value)
        try:
            verify_receipt(evidence, "roots", roots_receipt["result_sha256"])
        except Refusal as exc:
            if "PHASE_RECEIPT_DRIFT" not in str(exc):
                raise
            checks += 1
        else:
            raise AssertionError("receipt drift admitted")
    index = load_index(DEFAULT_INDEX)
    adapter_id = index["adapters"][0]["adapter_id"]
    if resolve_adapter(DEFAULT_INDEX, adapter_id).name != (
        "research_enforcement_activation.v1.json"
    ):
        raise AssertionError("indexed adapter resolution")
    checks += 1
    print("SELF_TEST_PASS checks=%s" % checks)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list-adapters", action="store_true")
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--adapter-id")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--root", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--baseline-manifest", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--noop-rehearsal", action="store_true")
    modes.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        if (
            any((args.list_adapters, args.adapter, args.adapter_id,
                 args.index != DEFAULT_INDEX, args.state, args.evidence_dir, args.root,
                 args.baseline_manifest, args.plan, args.noop_rehearsal,
                 args.resume))
        ):
            print(
                "REFUSE(SIGNED_RELEASE_CONVERGENCE): SELF_TEST_ARGUMENT_REFUSED",
                file=sys.stderr,
            )
            return 2
        return self_test()
    if args.list_adapters:
        if any((args.adapter, args.adapter_id, args.state, args.evidence_dir,
                args.root, args.baseline_manifest, args.plan,
                args.noop_rehearsal, args.resume)):
            print(
                "REFUSE(SIGNED_RELEASE_CONVERGENCE): LIST_ARGUMENT_REFUSED",
                file=sys.stderr,
            )
            return 2
        try:
            index = load_index(args.index)
            for row in index["adapters"]:
                print("%s\t%s\t%s" % (
                    row["adapter_id"], row["status"], row["path"]
                ))
            return 0
        except Refusal as exc:
            print("REFUSE(SIGNED_RELEASE_CONVERGENCE): %s" % exc, file=sys.stderr)
            return 2
    if args.adapter and args.adapter_id:
        print(
            "REFUSE(SIGNED_RELEASE_CONVERGENCE): ADAPTER_SELECTION_CONFLICT",
            file=sys.stderr,
        )
        return 2
    if not args.adapter and not args.adapter_id:
        print(
            "REFUSE(SIGNED_RELEASE_CONVERGENCE): ADAPTER_SELECTION_REQUIRED",
            file=sys.stderr,
        )
        return 2
    if not all((args.state, args.evidence_dir)) or not any(
        (args.plan, args.noop_rehearsal, args.resume)
    ):
        print(
            "REFUSE(SIGNED_RELEASE_CONVERGENCE): EXECUTION_ARGUMENTS_REQUIRED",
            file=sys.stderr,
        )
        return 2
    mode = "noop-rehearsal" if args.noop_rehearsal else "plan"
    try:
        adapter_path = args.adapter or resolve_adapter(args.index, args.adapter_id)
        return execute(
            adapter_path,
            args.state,
            args.evidence_dir,
            args.root,
            mode,
            args.resume,
            args.baseline_manifest,
        )
    except Refusal as exc:
        print("REFUSE(SIGNED_RELEASE_CONVERGENCE): %s" % exc, file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired:
        print("REFUSE(SIGNED_RELEASE_CONVERGENCE): COMMAND_TIMEOUT", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            "REFUSE(SIGNED_RELEASE_CONVERGENCE): INTERNAL_%s" % type(exc).__name__,
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

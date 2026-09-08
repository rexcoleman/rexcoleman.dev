from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "enumerate_signed_release_convergence.py"
INDEX = ROOT / "signed_release_convergence_index.json"
INVENTORY = ROOT / "signed_release_convergence_inventory.json"
SPEC = importlib.util.spec_from_file_location("enumerate_signed_release_convergence", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def repo_args(tmp_path: Path) -> list[str]:
    return [
        "--repo",
        f"govML={tmp_path / 'govML'}",
        "--repo",
        f"rexcoleman.dev={tmp_path / 'rexcoleman.dev'}",
    ]


def test_adapter_index_input_refuses_with_inventory_hint(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        tool.main(["--inventory", str(INDEX), *repo_args(tmp_path)])
    assert "REFUSE(INVENTORY_FILE_REQUIRED)" in str(exc.value)
    assert "signed_release_convergence_inventory.json" in str(exc.value)


def test_inventory_argument_is_required(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="INVENTORY_ARGUMENT_REQUIRED"):
        tool.main(repo_args(tmp_path))


def test_inventory_and_legacy_index_alias_are_mutually_exclusive(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit, match="INVENTORY_ARGUMENT_AMBIGUOUS"):
        tool.main(
            [
                "--inventory",
                str(INVENTORY),
                "--index",
                str(INVENTORY),
                *repo_args(tmp_path),
            ]
        )


def test_legacy_index_alias_still_reads_inventory(tmp_path: Path) -> None:
    planted = tmp_path / "inventory.json"
    value = json.loads(INVENTORY.read_text(encoding="utf-8"))
    value["repositories"] = {"govML": value["repositories"]["govML"]}
    planted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SystemExit, match="INVENTORY_REPOSITORY_SET_MISMATCH"):
        tool.main(["--index", str(planted), *repo_args(tmp_path)])

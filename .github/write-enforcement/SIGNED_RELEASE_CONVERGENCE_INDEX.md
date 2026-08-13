# Signed-release convergence index

`signed_release_convergence_index.json` is the canonical discovery surface for
the reusable signed-release convergence engine and its adapters. Start here
instead of reconstructing paths from an earlier release handoff.

The index is intentionally small and closed. It names the current engine,
operator documentation, focused tests, read-only workflow, this guide, and
every registered adapter. It also points to
`signed_release_convergence_inventory.json`, the broader cross-generation,
two-repository machinery inventory. The narrow adapter registry answers
"which current planner can I run?"; the broader inventory answers "which
reusable convergence mechanisms and prior proof suites already exist?"
Each adapter row has exactly three fields:

- `adapter_id`: the stable identifier validated from the adapter itself;
- `path`: a repository-relative JSON path below the index directory; and
- `status`: `active` or `retired`.

The engine resolves an active row when invoked with `--adapter-id`. A direct
`--adapter` path remains supported for compatibility, but indexed selection is
the normal route. `--list-adapters` validates the complete index and every
adapter before printing the registered rows. Unknown, duplicate, retired,
traversing, missing, mismatched, or extra-field rows refuse.

## Adding or changing an adapter

1. Add or update the adapter JSON under `adapters/`.
2. Add exactly one matching row to the machine index. Never reuse an existing
   identifier for different semantics.
3. Extend the focused tests for the adapter contract and planted refusals.
4. Update `SIGNED_RELEASE_CONVERGENCE.md` when the operating boundary changes.
5. Run the internal self-test and focused test file. The read-only
   `signed-release-convergence` workflow repeats both on the pull request.

The index is navigation and contract metadata, not release authority. It does
not merge, tag, approve, issue, install, or prove a target project green.

## Cross-generation inventory and reconciliation

The inventory has 17 closed rows spanning s88, s127, s131, s132, s149, s153,
and s154 in govML and rexcoleman.dev. Each row names a stable identity, remote
repository/default branch, path, session generation, kind, semantic discovery
markers, and the tested properties it supplies. The six required properties
are hermetic execution, identity binding, resume, refusal, poststate, and
evidence. `untested_properties` is derived from their status map; it is empty
only while each property remains backed by a registered test.

`enumerate_signed_release_convergence.py` reconciles the inventory by two
independent Git methods against fetched `origin/main`: tree identity via
`git ls-tree`, and semantic discovery via fixed-string `git grep` markers.
It emits both counts, their percentage delta, and one row per result; any
missing row or delta above five percent is nonzero. This is the required
preflight before adding a new convergence implementation. Reuse a registered
engine/adapter/test/evidence row, and add a row only when no existing mechanism
covers the requirement.

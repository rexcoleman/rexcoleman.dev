# Signed-release convergence index

`signed_release_convergence_index.json` is the canonical discovery surface for
the reusable signed-release convergence engine and its adapters. Start here
instead of reconstructing paths from an earlier release handoff.

The index is intentionally small and closed. It names the current engine,
operator documentation, focused tests, read-only workflow, this guide, and
every registered adapter. Each adapter row has exactly three fields:

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

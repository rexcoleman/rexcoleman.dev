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

The active registry contains the original REA authority adapter, its s155
registration successor, the Band C M1/row-26 257-member successor, the W2
project-bundle basis-resolution successor, its derived-authority-generator
successor, the two s157 dependent-project adapters for NGA and RER, their
population-257 and population-259 successors, and the s165 population-259 AML
dependent adapter. The population-259 identities
bind the PR 759 Moonshots build roles plus both govML role checklists. A
population change always gets a new stable
adapter identity; the 251- and 255-member adapters remain
auditable without being silently redefined. The dependent adapters use schema
v2: in addition to the unchanged
five-root signed-authority plan they close over the exact dependent repository,
default branch, project-owned runner and preflight argument, required
`SIGNED_BUNDLE` source, and named refusal. The engine records that identity in
the contract receipt but keeps release/install mutation outside the planner.

## Adding or changing an adapter

1. Add or update the adapter JSON under `adapters/`.
2. Add exactly one matching row to the machine index. Never reuse an existing
   identifier for different semantics.
3. Extend the focused tests for the adapter contract and planted refusals. A
   dependent adapter must cover hermetic execution, exact target identity,
   resume, refusal, source-root poststate, and durable contract evidence.
   A population successor uses the closed
   `<project>-generation-<generation>-population-<count>-v1` identity; the
   loader refuses when the suffix count and `expected_member_count` diverge.
4. Update `SIGNED_RELEASE_CONVERGENCE.md` when the operating boundary changes.
5. Run the internal self-test and focused test file. The read-only
   `signed-release-convergence` workflow repeats both on the pull request.

The index is navigation and contract metadata, not release authority. It does
not merge, tag, approve, issue, install, or prove a target project green.

## Cross-generation inventory and reconciliation

The inventory has 28 closed rows spanning s88, s127, s131, s132, s149, s153,
s154, s155, s157, and s165 in govML and rexcoleman.dev. Each row names a stable identity, remote
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

The s165 row registers `rehearse_generation5_ruleset_revert.py`. It reuses the
generation-5 manifest builder, derives all five immutable member commits from
the frozen manifest, clones only from the five gios-dev object stores, and
double-builds from a supplied post-revert ruleset file. Its normal invocation
requires only `--ruleset-json`; the output location has a deterministic default.
It refuses a non-empty bypass, member drift, a third changed manifest field, or
non-deterministic output, and performs no remote or installed-state mutation.

The second s165 row registers the population-259
`adversarial_ml_landscape` dependent adapter. It binds the Moonshots
`--converge-enforcement` genesis transition from a committed
`PENDING_SIGNED_BUNDLE` sentinel to the authenticated bundle's exact govML
commit, requires refusal rollback to the original governance bytes, and retains
the dependent project's own post-issuance runner as the acceptance surface.

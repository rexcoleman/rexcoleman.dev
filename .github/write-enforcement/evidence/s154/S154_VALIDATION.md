# S154 signed-release convergence validation

Status: IMPLEMENTATION VALIDATED; PROTECTED PUBLICATION PENDING

Recorded: 2026-08-13 UTC

Authority: owner direction to downstream Coach s154, following kernel coach 65,
to use and improve s153's reusable signed-release convergence infrastructure
and create or update its index and index description.

## Outcome before publication

The owning repository had a reusable engine, one generation-5 REA adapter,
operator documentation, focused tests, and a read-only workflow. It had no
machine index or index contract, and repository-wide search by the owner's
description did not route to the implementation.

S154 added a closed machine index, a human index guide, indexed adapter
selection, validated adapter listing, exact metadata identity checks, active
versus retired status, and typed refusal for unknown, duplicate, misplaced,
traversing, mismatched, or ambiguous selections. The direct adapter-path
interface remains compatible. The existing workflow now watches the index and
guide.

## Exact validation

- Python compilation: exit 0.
- Internal self-test: `SELF_TEST_PASS checks=9`, exit 0.
- Indexed adapter listing: one active
  `research-enforcement-activation-generation-5` row, exit 0.
- Focused suite: 25 passed, exit 0.
- Full write-enforcement suite: 460 passed, 1 skipped, exit 0.
- Final indexed no-op rehearsal: exit 0, all seven phases complete, two
  byte-identical manifest builds, 248 members, frozen manifest digest
  `469b1b4a48ba50364d8facbd8b6569d91f990ae133da955dec7e92858126b44f`,
  unchanged poststate, `remote_mutation=false`, `owner_action=false`.
- Planted wrong-baseline attempt: exit 2 before any phase completed with
  `NOOP_ROOT_COMMIT_REFUSED` for the mismatched govML identity. The refused
  state was preserved and a new state filename was used for the correct run.

Durable exact engine outputs are adjacent:

- `indexed_noop_summary.json`;
- `indexed_noop_state.json`;
- `wrong_baseline_refusal_state.json`.

The disposable seven-phase receipt tree remains at
`/tmp/s154_release_noop/evidence_final`. The durable summary and state preserve
its receipt hashes; the complete transient tree is not a publication input.

## Facts versus inference

Fact: the prior repository tree had no path containing an infrastructure index
for this engine. Fact: the new index is machine-validated by the engine and its
CI tests. Fact: the final exact engine bytes completed the no-op rehearsal.
Inference: indexed discovery should reduce future reconstruction time; this
task does not measure future operator latency.

## Boundaries and risks

This change performs no merge, tag, approval, issuance, installation, target
mutation, or owner action. It does not convert the deterministic planner into
release authority. The index has one active adapter; future adapters still
require an explicit registered row, tests, review, and protected publication.

### GPL-47: What This Does NOT Prove

This validation does not prove a future signed-member change correct, a future
adapter complete, a target repository green, or any issuance authorized. The
no-op rehearsal proves exact rebuild and unchanged poststate for the frozen
generation-5 inputs only. It does not replace independent review, protected
approval, signing, installation, or target verification.

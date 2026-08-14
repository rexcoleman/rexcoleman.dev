# s157 Band B Executor handoff

Status: **COMPLETE — NGA and RER are active adapters in the existing s153
signed-release convergence registry, the real planner passed for both, and the
implementation is merged into rexcoleman.dev `main`.**

Authority: kc-66 single-shot dispatch to s157 Coach; `/root` delegated Band B
only to `/root/band_b_executor`. This executor did not begin Bands C through F,
did not create a parallel index or engine, and used no owner action. The task
was machine-executable throughout.

## Published outcome

- Starting `rexcoleman.dev` authority: live `origin/main`
  `9e9419dc0898ad17239a4b285b3af61cd488d2d2`.
- Implementation commit:
  `e15d40c48bc9b959e27a1326ac63f5d61ea8356e`.
- Protected PR: <https://github.com/rexcoleman/rexcoleman.dev/pull/147>.
- Exact-head protected check: workflow `signed-release-convergence`, job
  `verify`, conclusion `SUCCESS`, run 31835761966, job 94881599625.
- Merge commit: `c496a19dde63d28c668d0bfa4437febac5682d68`.
- `git merge-base --is-ancestor e15d40c origin/main` raw exit: `0`.

The existing s153 engine remains the only engine. Its existing machine index,
guide, broader inventory, and workflow remain the discovery and verification
surfaces.

## Exact changed machinery

1. `.github/write-enforcement/adapters/newsletter_generation_architecture.generation-5.json`
2. `.github/write-enforcement/adapters/research_engine_release.generation-5.json`
3. `.github/write-enforcement/signed_release_convergence.py`
4. `.github/write-enforcement/signed_release_convergence_index.json`
5. `.github/write-enforcement/signed_release_convergence_inventory.json`
6. `.github/write-enforcement/SIGNED_RELEASE_CONVERGENCE.md`
7. `.github/write-enforcement/SIGNED_RELEASE_CONVERGENCE_INDEX.md`
8. `.github/write-enforcement/tests/test_signed_release_convergence.py`

The compatible adapter v2 schema adds one closed `dependent_project` object.
It validates and evidence-binds the project identifier, matching GitHub
repository, default branch, project-owned runner, exact preflight argument,
required signed source, and named refusal. Existing v1 adapters and their
contract-receipt shape remain unchanged.

| Adapter ID | Repository/default | Own runner | Required source | Named refusal |
| --- | --- | --- | --- | --- |
| `newsletter-generation-architecture-generation-5` | `rexcoleman/newsletter_generation_architecture` `main` | `scripts/run_gates.sh --engine-preflight` | `SIGNED_BUNDLE` | `F09` |
| `research-engine-release-generation-5` | `rexcoleman/research_engine_release` `master` | `scripts/run_gates.sh --engine-preflight` | `SIGNED_BUNDLE` | `AUTHORITY_LAPSED` |

Both adapters close over generation 5 and the current 255-member registered
authority population. The planner still takes the same five authoritative
roots and performs no dependent mutation. REA's registered successor
transition owns later release/install/default-branch verification.

## Required five-repository search

Every search used the fetched default ref, not a shared working checkout. The
pre-edit identities were:

| Repository | Ref | Commit |
| --- | --- | --- |
| Moonshots | `origin/main` | `19e5e78305dcda3a0fb944d35632834571e88b7e` |
| govML | `origin/main` | `1444ea8344f53fb4609a47e844034d8ea0457452` |
| REA | `origin/master` | `6d7c27b30460c6cdc9efed32af6ca76378e358b3` |
| rexcoleman.dev | `origin/main` | `9e9419dc0898ad17239a4b285b3af61cd488d2d2` |
| newsletter | `origin/main` | `942492f7eec60f1e2caf002eec171dfd39295fbd` |

Exact fixed-string file counts before editing:

| Repository | `signed_release_convergence.py` | index filename | NGA adapter ID | RER adapter ID |
| --- | ---: | ---: | ---: | ---: |
| Moonshots | 5 | 0 | 0 | 0 |
| govML | 0 | 0 | 0 | 0 |
| REA | 9 | 6 | 4 | 5 |
| rexcoleman.dev | 8 | 6 | 0 | 0 |
| newsletter | 0 | 0 | 0 | 0 |

The apparent absence was therefore specific to the rex registry, not a global
absence. REA already named both required IDs in the registered s157 transition
and its documentation. After the implementation commit, each new ID occurs in
exactly four task-head files: the operating guide, its adapter JSON, the
existing machine index, and the focused tests.

## Tests and raw exits

### Registry and focused closure

`signed_release_convergence.py --list-adapters` raw exit `0`:

```text
research-enforcement-activation-generation-5 active adapters/research_enforcement_activation.v1.json
research-enforcement-activation-generation-5-registration-v1 active adapters/research_enforcement_activation.registration-v1.json
newsletter-generation-architecture-generation-5 active adapters/newsletter_generation_architecture.generation-5.json
research-engine-release-generation-5 active adapters/research_engine_release.generation-5.json
```

- Internal self-test: `SELF_TEST_PASS checks=9`, raw exit `0`.
- Focused convergence file: `42 passed`, raw exit `0`.
- Complete protected-workflow test set: `213 passed, 1 skipped`, raw exit `0`.
- The named cross-generation closure test plus dropped-property companion:
  `2 passed, 40 deselected`, raw exit `0`.
- Python compilation and `git diff --check`: raw exit `0`.

The new coverage contains positive identity checks, six planted target-route
drifts, exact hermetic-source-set assertions, refusal followed by exact resume
for each adapter, unchanged-root poststate, and durable dependent identity in
the contract receipt.

### Real s153 plan — NGA

Raw exit `0`:

```text
SIGNED_RELEASE_CONVERGENCE_PASS adapter=newsletter-generation-architecture-generation-5 mode=plan manifest_digest=9dc4123be34425c0bfe4969ff14fe1da8c1757bac3e68966294cdae79feed094 member_count=255 remote_mutation=false owner_action=false
```

Exact complete-state resume raw exit `0` with the same line and digest.
Canonical summary content:

```json
{"adapter_id":"newsletter-generation-architecture-generation-5","adapter_sha256":"68a5b7b5b7f04ed24c32e616036f9c5466db78e3b99d15006c3514ec7ddb52bc","contract":{"anti_spin":"not-applicable-deterministic","bcs_surface":"untouched","dependent_project":{"default_branch":"main","named_refusal":"F09","preflight_arguments":["--engine-preflight"],"project_id":"newsletter_generation_architecture","repository":"rexcoleman/newsletter_generation_architecture","required_source":"SIGNED_BUNDLE","runner_path":"scripts/run_gates.sh"},"deterministic":true,"manifest_digest":"9dc4123be34425c0bfe4969ff14fe1da8c1757bac3e68966294cdae79feed094","manifest_sha256":"831c8b4d38d6d051db4512a2177019dd66e506b8eed149cf95e695d5705adac7","member_count":255,"noop_equal":false,"owner_action":false,"remote_mutation":false},"mode":"plan","next_remote_step":"manifest-only-pr-after-independent-review","phases":["roots","impact","hermetic","manifest-a","manifest-b","contract","poststate"],"schema_version":"rea.signed-release-convergence-summary.v1","status":"PASS","tool_sha256":"c7f864d7009daadc250650b799bee01f520c62c3bf5540859c6f2d951674b63c"}
```

The source summary SHA-256 was
`b37ef6d0e57a8d12e8ffa1f45da334d94d4634a2fcd0342a4635e193e277045a`.

### Real s153 plan — RER

Raw exit `0`:

```text
SIGNED_RELEASE_CONVERGENCE_PASS adapter=research-engine-release-generation-5 mode=plan manifest_digest=9dc4123be34425c0bfe4969ff14fe1da8c1757bac3e68966294cdae79feed094 member_count=255 remote_mutation=false owner_action=false
```

Exact complete-state resume raw exit `0` with the same line and digest.
Canonical summary content:

```json
{"adapter_id":"research-engine-release-generation-5","adapter_sha256":"8777f8f0ed655f3bf024701239ee7ea7e95f5e959b172c4d097b8d3ba8396f9a","contract":{"anti_spin":"not-applicable-deterministic","bcs_surface":"untouched","dependent_project":{"default_branch":"master","named_refusal":"AUTHORITY_LAPSED","preflight_arguments":["--engine-preflight"],"project_id":"research_engine_release","repository":"rexcoleman/research_engine_release","required_source":"SIGNED_BUNDLE","runner_path":"scripts/run_gates.sh"},"deterministic":true,"manifest_digest":"9dc4123be34425c0bfe4969ff14fe1da8c1757bac3e68966294cdae79feed094","manifest_sha256":"831c8b4d38d6d051db4512a2177019dd66e506b8eed149cf95e695d5705adac7","member_count":255,"noop_equal":false,"owner_action":false,"remote_mutation":false},"mode":"plan","next_remote_step":"manifest-only-pr-after-independent-review","phases":["roots","impact","hermetic","manifest-a","manifest-b","contract","poststate"],"schema_version":"rea.signed-release-convergence-summary.v1","status":"PASS","tool_sha256":"c7f864d7009daadc250650b799bee01f520c62c3bf5540859c6f2d951674b63c"}
```

The source summary SHA-256 was
`56f2c6f71d1cac51c6e2278d8cbdf73fe13090b316f23cb2e750474598dfd4c3`.

### Planted negative and cross-generation reconciliation

An isolated copy of NGA's completed evidence had the roots receipt hash
planted to zero. Resume refused before any phase execution:

```text
REFUSE(SIGNED_RELEASE_CONVERGENCE): PHASE_RECEIPT_DRIFT:roots
RAW_EXIT=2
```

After PR 147 merged, the registered two-method enumerator ran against govML
`origin/main` and rexcoleman.dev `origin/main`:

```text
inventory_entries=20
method_a_tree_identity_count=20
method_b_semantic_search_count=20
delta_percent=0.0
within_five_percent=true
RAW_EXIT=0
```

Both new s157 adapter rows were `tree_found=true` and
`semantic_found=true`. The six-property map remains fully `tested` and
`untested_properties` remains empty.

### REA registered-transition integration

The merged REA transition was fired read-only against the current installed
state and this adapter tree. It changed from the Band A missing-adapter refusal
to raw exit `0`:

```text
verdict=READY_FOR_REGISTERED_PROPAGATION_BINDING
renewal_epoch=61
renewal_state_digest=3c4afe36b729176084d2fc0a39d27104829efba906e925de7cbc97212982e91d
mutation_performed=false
engine_sha256=c7f864d7009daadc250650b799bee01f520c62c3bf5540859c6f2d951674b63c
index_sha256=4202de8fcc1779faa45f4df6f2f139cc779080f35d75d3ad7a59ce9b17c13068
nga_adapter_sha256=68a5b7b5b7f04ed24c32e616036f9c5466db78e3b99d15006c3514ec7ddb52bc
rer_adapter_sha256=8777f8f0ed655f3bf024701239ee7ea7e95f5e959b172c4d097b8d3ba8396f9a
RAW_EXIT=0
```

## Exact REA re-entry action

Re-fire the registered `scripts/s157_dependent_successor_propagation.py`
transition using rexcoleman.dev `origin/main`, then bind the resulting closed
adapter set into the renewal successor path. For each target, execute the
registered convergence/release/materialization route, land the target change
through its protected default branch, and fire that project ref's own
`scripts/run_gates.sh --engine-preflight`. G10 is established only when NGA
`main` no longer emits `F09` and RER `master` no longer emits
`AUTHORITY_LAPSED`, with `source=SIGNED_BUNDLE` on each project-owned runner.

This is the next action for REA propagation; it does not require an owner.

## Facts, boundaries, and unresolved dependent state

Measured facts:

- Both adapters are indexed, validated, tested, exercised through real plans,
  and merged on rexcoleman.dev `main`.
- Both plans used all five clean authority roots, deterministic double-builds,
  exact 255-member closure, unchanged-root poststate, and no remote mutation.
- REA's readiness transition now sees both active adapter identities and passes.
- The protected implementation PR passed its exact-head convergence workflow.

Still outside Band B:

- Adapter registration does not merge NGA PR 13 or RER PR 3.
- Adapter planning does not install bytes or establish G10 on either dependent
  default branch.
- The REA renewal-to-dependent dispatch binding remains the next Band A
  re-entry named above.
- No claim is made about Bands C through F, the frozen corpus remeasurement,
  write-side repair, quality loop, or write-boundary design approval.

No credentials were printed or persisted. No Mac Mini or BCS surface was
touched. No shared dirty checkout was used as execution truth. The
rexcoleman.dev task worktree and five authority roots were clean at every
planner roots/poststate check.

### GPL-47: What This Does NOT Prove

A passing non-mutating convergence plan proves exact authority inputs,
hermetic tests, deterministic manifest closure, resumable evidence, and
unchanged source poststate. It does not prove a dependent project has installed
the authority, passed its own substantive gates, or landed on its default
branch. `READY_FOR_REGISTERED_PROPAGATION_BINDING` proves the closed adapter
precondition, not propagation. G10 remains separate and must be measured on
NGA `main` and RER `master` by their own runners.

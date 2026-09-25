# s250 population-305 Stage 5 template successor evidence

## Authority and boundary

Coach s250 implemented the rexcoleman.dev source-registration side requested by
kernel coach 99 after govML PR #240 merged. This change prepares, but does not
freeze, tag, issue, finalize, install, or activate a signed release. It does
not edit any REA Stage artifact or fill any Branch C Stage 5 content.

The authenticated source prerequisite is govML PR #240, head
`c65807670d97f0950c8a276b7aca4fe3bf8ea0b9`, merged as
`13a78fa5d2f6055d09da0f136dab620819ee26da`. Both required
`artifact-integrity-exact-commit` checks passed.

## Exact successor contract

The immutable population-300 role-checklist contract is extended by exactly
five canonical govML subjects:

- `stage5-template-artifact-contract` ->
  `templates/build/ARTIFACT_CONTRACT.tmpl.md`
- `stage5-template-runtime-emit-spec` ->
  `templates/build/RUNTIME_EMIT_SPEC.tmpl.md`
- `stage5-template-acceptance-criteria` ->
  `templates/build/ACCEPTANCE_CRITERIA.tmpl.md`
- `stage5-template-construction-manifest-spec` ->
  `templates/build/construction_manifest_spec.tmpl.json`
- `stage5-template-construction-manifest` ->
  `templates/build/construction_manifest.tmpl.json`

`stage5_build_template_successor_members()` produces the exact closed
305-member map. `validate_stage5_build_template_member_ids()` rejects every
omission and predecessor population. The mode gate requires all five subjects
to be regular `100644` blobs and rejects partial, substituted, or executable
template sets.

The manifest builder exposes the mutually exclusive
`--stage5-build-template-successor` selector. The convergence adapter loader
and impact selector recognize only that exact registered flag. Six active
population-305 adapters cover REA, AML, ABL, NHP, NGA, and RER. Each differs
from its population-300 predecessor in only `adapter_id`,
`expected_member_count`, and `manifest_builder_flag`; the predecessor rows
remain active for audit.

## Files and controls

- `.github/write-enforcement/member_contract.py`: exact five-member successor,
  closed ID validation, mode validation, terminal manifest selection, and
  managed-live closure admission.
- `.github/write-enforcement/build_frozen_manifest.py`: distinct selector,
  mutual exclusion, exact member validation, and generation-5 activation.
- `.github/write-enforcement/signed_release_convergence.py`: closed adapter
  vocabulary and exact selector dispatch.
- `.github/write-enforcement/signed_release_convergence_index.json`: six
  active population-305 rows.
- `.github/write-enforcement/adapters/*.population-305-v1.json`: six exact
  successor adapters.
- `SIGNED_RELEASE_CONVERGENCE.md` and
  `SIGNED_RELEASE_CONVERGENCE_INDEX.md`: successor semantics and failure class
  20.
- Five affected test modules prove exact membership, all planted omissions,
  wrong modes, predecessor refusal, flag mutual exclusion, index closure,
  adapter identity, terminal-reviewer selection, and real five-root build.

## Verification

Focused affected suite:

`python3 -m pytest -q` over
`test_member_contract.py`, `test_build_frozen_manifest.py`,
`test_independent_review.py`, `test_signed_release_convergence.py`, and
`test_s131_convergence.py` completed with `490 passed, 1 skipped` in 140.96
seconds.

Registered convergence self-test:

`python3 .github/write-enforcement/signed_release_convergence.py --self-test`
completed with `SELF_TEST_PASS checks=9`.

The six adapter diffs were parsed and compared mechanically; each changed
exactly the three population-bearing fields. The convergence index parsed as
JSON, and `git diff --check` completed cleanly.

## Remaining release boundary

The source successor alone cannot be issued safely. REA's signed
`s157_dependent_successor_propagation.py` pins both the rex convergence engine
commit/digest and five population-300 dependent adapter IDs. After this rex PR
merges, a separate non-live REA source PR must advance those exact pins and
prove the read-only transition before kernel coach 99 performs any release
issuance or history finalization. The exact merged rex commit and engine digest
must be derived after merge; no moving-branch pin is admissible.

No issuance, finalization, runtime repoint, installed-state mutation, release
tag, or owner action occurred in this work.

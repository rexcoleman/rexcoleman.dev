# s232 govML template manifest-successor handback

## Identity and outcome

- Role: downstream general-purpose Builder under s232 Coach and kernel Coach 94.
- Owning repository/worktree: `/tmp/rea_s232_rex_manifest`.
- Protected starting authority: `origin/main` and worktree `HEAD` both `69825941d3a5ff6b09a6fa6b92b8369812c44b37` after an explicit fetch.
- Outcome: source prerequisite and the independent verifier's exact-template-mode correction are implemented and tests green. No merge, freeze, tag, issue, install, activation, live-state write, or change to `/tmp/rea_s232_rex_packet` was performed.
- Reality versus intent: this work registers a 296-member successor. The live generation-5 manifest is still the immutable 291-member predecessor and therefore cannot authenticate these five templates until the registered publication/freeze/issuance sequence completes.

## Architecture finding

No smaller already-registered authenticated consumer route was found. The only exact-Git-object reader in this surface is the manifest builder's release-construction path; it is not a signed consumer authorization for arbitrary paths. The issuer and independent reviewer derive one exact closed member set from the registered terminal selector. The five canonical template paths have no existing signed byte-identical alias. Adding one narrow successor layer is therefore the source-owned registered route; historical population 291 and all its adapters/manifests remain byte-unchanged.

## Exact new member set

The successor is `research_working_root_template_successor_members()`, which strictly extends `final_runtime_rollout_successor_members()` from 291 to 296 with exactly:

1. `research-template-observation-log` -> `govML:templates/strategy/OBSERVATION_LOG.tmpl.md`
2. `research-template-question-spec` -> `govML:templates/strategy/RESEARCH_QUESTION_SPEC.tmpl.md`
3. `research-template-landscape-assessment` -> `govML:templates/strategy/LANDSCAPE_ASSESSMENT.tmpl.md`
4. `research-template-hypothesis-registry` -> `govML:templates/core/HYPOTHESIS_REGISTRY.tmpl.md`
5. `research-template-experimental-design` -> `govML:templates/core/EXPERIMENTAL_DESIGN.tmpl.md`

Any one observed template marker selects the complete 296-member set. Missing, extra, renamed, substituted, colliding, dirty, unreachable, wrong-mode, or digest-divergent members refuse before manifest emission or issuance.

## Changed paths

- `.github/write-enforcement/member_contract.py`
- `.github/write-enforcement/build_frozen_manifest.py`
- `.github/write-enforcement/signed_release_convergence.py`
- `.github/write-enforcement/signed_release_convergence_index.json`
- `.github/write-enforcement/SIGNED_RELEASE_CONVERGENCE.md`
- `.github/write-enforcement/SIGNED_RELEASE_CONVERGENCE_INDEX.md`
- `.github/write-enforcement/adapters/adversarial_ml_landscape.population-296-v1.json`
- `.github/write-enforcement/adapters/agent_boundary_learning_landscape.population-296-v1.json`
- `.github/write-enforcement/adapters/newsletter_generation_architecture.population-296-v1.json`
- `.github/write-enforcement/adapters/newsletter_hybrid_path.population-296-v1.json`
- `.github/write-enforcement/adapters/research_enforcement_activation.population-296-v1.json`
- `.github/write-enforcement/adapters/research_engine_release.population-296-v1.json`
- `.github/write-enforcement/tests/test_member_contract.py`
- `.github/write-enforcement/tests/test_build_frozen_manifest.py`
- `.github/write-enforcement/tests/test_signed_release_convergence.py`
- `.github/write-enforcement/tests/test_independent_review.py`
- `.github/write-enforcement/tests/test_s131_convergence.py`

Each new adapter is mechanically identical to its population-291 predecessor except for `adapter_id`, `expected_member_count` (296), and `manifest_builder_flag` (`--research-working-root-template-successor`). Existing adapters are preserved.

## Controls and evidence

- Exact-set positive: all five rows, exact paths, count 296.
- Strict-subset negatives: each individual omission refuses.
- Substitution negative: wrong repository/path refuses.
- Historical preservation: population 291 remains exactly equal to the prior final-runtime selector and rejects template additions.
- Commit binding: tests open every member with `git show <commit>:<path>` semantics and compare committed bytes; dirty template working-tree divergence refuses.
- Remote reachability: the production builder retains the per-repository GitHub commit reachability check before it prints only member identity metadata.
- Freeze determinism: the real five-root 296-member builder is run twice and the emitted manifest bytes must be identical.
- Secret non-disclosure: a planted secret member is absent from stdout, stderr, and manifest bytes; only its digest and byte length are emitted.
- Independent review: the terminal adapter and selector are structurally derived without executing reviewed source. The still-live 291 manifest is explicitly tested as the exact prior population and refused as a 296 candidate.
- No-write-on-refusal: existing builder/issuer tests plus the new dirty and strict-subset cases assert refusal before successor output.
- Exact template modes: the shared owning contract requires each of the five new
  templates to be a regular Git blob with mode `100644`. Each individual
  `100755` plant refuses through both the frozen-population opener and issuer;
  missing and symlink plants refuse, and a real five-root builder plant leaves
  no output manifest. Historical population 291 and unrelated executable
  members retain their prior mode behavior.

## Raw command results

Initial focused repair:

`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q .github/write-enforcement/tests/test_member_contract.py .github/write-enforcement/tests/test_build_frozen_manifest.py`

Result: exit 0, `185 passed` after the 296 managed-alias allowlist correction.

Transition tests:

`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q .github/write-enforcement/tests/test_signed_release_convergence.py .github/write-enforcement/tests/test_independent_review.py -x`

Result: exit 0, `250 passed in 30.99s`.

Exact 296 builder controls:

`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q .github/write-enforcement/tests/test_build_frozen_manifest.py .github/write-enforcement/tests/test_s131_convergence.py -x`

Result: exit 0, `35 passed, 1 skipped in 39.67s`. The skip is the existing environment-dependent case, not a failed predicate.

Final combined verification:

`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q .github/write-enforcement/tests/test_member_contract.py .github/write-enforcement/tests/test_build_frozen_manifest.py .github/write-enforcement/tests/test_signed_release_convergence.py .github/write-enforcement/tests/test_independent_review.py .github/write-enforcement/tests/test_s131_convergence.py tests/test_s111_signed_runtime_members.py`

Result after the exact-mode repair: exit 0,
`457 passed, 1 skipped in 84.32s`.

The focused mode/contract/builder selection separately passed:
`199 passed, 1 skipped in 68.26s`.

Python compilation of the owning modules and changed tests passed using an
external bytecode cache. JSON parsing passed for the convergence index and all
six population-296 adapters (`JSON_PASS index=1 adapters=6`).
`git diff --check` exited 0 with no output.

## Exact registered next actions

These actions remain pending and require their normal authority; this Builder did not perform them:

1. Review and publish this rex source change through its protected-main PR path. Do not freeze from the dirty worktree.
2. Publish the already-prepared source prerequisites in their owning govML/Moonshots/REA repositories, then fetch five clean authoritative roots at the final protected commits.
3. Refresh the six population-296 adapter repository pins/digests through the registered propagation source, preserving the exact three-field derivation and the protected successor flag.
4. Run `.github/write-enforcement/signed_release_convergence.py` in registered `--plan` mode using `research-enforcement-activation-generation-5-population-296-v1` and the five exact clean roots. Require its hermetic suite, reachability proofs, root poststate, and two byte-identical manifest builds.
5. Review the candidate manifest and receipts, then create the distinct manifest-only rex commit containing only `.github/write-enforcement/frozen_bundle_manifest.generation-5.json` and `.governance/pre_commit_boundary.json` as required by the independent-review boundary.
6. Run `.github/write-enforcement/independent_review.py` against the exact open PR head and exact two-file digest; merge only after its registered checks pass.
7. Derive the protected annotated generation-5 tag from the reviewed manifest feature commit, then use the hosted issuer workflow with the authenticated installed predecessor. Environment approval remains the owner gate.
8. Authenticate, install, consume, and verify the resulting successor through the registered rollout/consumer path. Only that later measured adoption can close the original template-manifest prerequisite.

## Boundaries and dirty state

The worktree started clean. All listed modifications are from this task. No generated `__pycache__` remains. No manifest, boundary receipt, key, credential, signature, packet, governance live state, or historical lineage artifact was edited. Credential values were never read or printed.

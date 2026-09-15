# s232 rexcoleman.dev population-296 independent verification

## Authority and verdict

- Role: independent verifier under s232 Coach; no Builder authority used.
- Worktree: `/tmp/rea_s232_rex_manifest`.
- Branch: `fix/s232-govml-template-members`.
- Audited HEAD and `origin/main`: `69825941d3a5ff6b09a6fa6b92b8369812c44b37`.
- Verification verdict at audit time: **BLOCKED — one reproducible source defect**. The five-member/count/path/commit/digest/length successor was otherwise coherent, but a canonical research template committed with executable mode `100755` was accepted by both the manifest builder's frozen-population opener and the issuer.
- Current correction status: **RESOLVED by the subsequent authorized Builder pass**. The owning shared contract now requires exact `100644` for only the five new template members, and the focused and full suites pass with discriminating opposite controls.
- This verification made no tracked-source edit, commit, push, PR, merge, freeze, tag, issue, install, activation, live-state write, or credential read. This report is the only repository file added by the verifier.

## Proven defect

`build_frozen_manifest.py:97-110` accepts either Git tree mode `100644` or `100755` for every regular member. `open_frozen_population()` records the mode and calls `validate_managed_live_member_aliases()` at line 154, but the five new template members are not managed-live aliases and have no exact `100644` predicate. `issue_wea.py` uses the same permissive committed-mode reader and the same alias-only mode validation. The population-296 manifest rows bind path, commit, digest, and length, but contain no mode field.

Independent plant 1 changed only `govML:templates/strategy/OBSERVATION_LOG.tmpl.md` from `100644` to `100755`, committed it in an isolated complete 296-member fixture, and invoked the real `open_frozen_population()`:

```text
ACCEPTED_EXECUTABLE_TEMPLATE member=research-template-observation-log count=296
```

Independent plant 2 built and verified a complete 296-member issuer fixture, then committed the same executable-mode change and updated only that row's commit to the new exact commit. Digest, length, path, and bytes stayed valid. The real issuer accepted all 296 members:

```text
ISSUER_PROBE_PASS refused=subject,commit,digest,length
ISSUER_MODE_DEFECT accepted=100755 member=research-template-observation-log
```

Probe artifacts are `/tmp/rex296_mode_probe.py` and `/tmp/rex296_issuer_probe.py`. They are outside the repository and do not alter production or tracked source.

Required source correction: define an exact `100644` source-mode contract for all five `RESEARCH_WORKING_ROOT_TEMPLATE_ADDITIONAL_MEMBERS`, enforce it from both build and issuer validation before manifest output or issuance, and add a full successor test that plants `100755` independently for each of the five templates and asserts no output. A symlink/tree-mode negative should remain alongside it. Do not merely add a test-local assertion.

## Confirmed successor properties

- `research_working_root_template_successor_members()` extends the unchanged `final_runtime_rollout_successor_members()` from exactly 291 to exactly 296 with only the five requested canonical govML paths.
- Each observed new member ID selects the complete 296-member contract through `production_members_for_manifest()`; each individual omission and forged ID refuses.
- The source selector detects member-ID and subject collisions.
- All six population-296 adapters are byte-for-byte equal to their population-291 predecessors except for exactly three derived fields: `adapter_id`, `expected_member_count=296`, and `manifest_builder_flag=--research-working-root-template-successor`.
- All six adapters resolve through the closed convergence index and the registered workflow watches adapter, index, builder, member-contract, reviewer-test, and convergence-test paths.
- Historical population-291 adapters, the live 291-member frozen manifest, and `.governance/pre_commit_boundary.json` are byte-identical to HEAD. The current live manifest is explicitly tested as the exact prior population and refused as a 296 candidate.
- Wrong subject, nonexistent 40-hex commit, digest mismatch, and byte-length mismatch all refused in the real complete 296-member issuer fixture.
- Remote reachability accepts only an exact GitHub commit response and refuses nonzero, empty, or mismatched responses before manifest-file creation. Builder construction obtains each selected commit from the validated root HEAD.
- Two real complete 296-member builds are byte-identical. The builder emits identity metadata, digest, and length but not member bytes; a planted secret was absent from stdout, stderr, and manifest content.
- The independent reviewer derives the terminal selector and member union structurally from AST without executing reviewed `member_contract.py`; its structural non-execution plant remains active and green.
- No unrelated manifest, boundary, workflow, credential, issuance, installation, or live-state surface is in the changed set.

The contract-level probe printed:

```text
CONTRACT_PROBE_PASS counts=291,296 observed_force=5 omissions=5 substitutions=5 collisions=2 adapters=6 historical_files=8 reviewer=structural
```

Here `substitutions=5` means forged member-ID substitution at the closed-set predicate. Exact repository/path substitution was separately exercised at the issuer boundary and refused. The ID validator is intentionally named `validate_research_working_root_template_member_ids`; it is not treated as the subject oracle.

## Fresh test evidence

Focused combined suite:

```text
450 passed, 1 skipped in 54.03s
```

The one skip is the pre-existing environment-dependent case already declared by the suite; no new test skipped, xfailed, or xpassed. The combined selection covered:

- `test_member_contract.py`
- `test_build_frozen_manifest.py`
- `test_signed_release_convergence.py`
- `test_independent_review.py`
- `test_s131_convergence.py`
- `tests/test_s111_signed_runtime_members.py`

`git diff --check HEAD --` exited 0 with no output.

## Modified-test weakening audit

The full diff has 43 deleted lines: 41 are in tests and two are in `member_contract.py`. Every deleted test line was inspected.

- `test_build_frozen_manifest.py`: three deleted lines extend the existing population parametrization and selector/digest branches from 291 to 296. The prior 273/290/291 assertions remain.
- `test_independent_review.py`: 27 deleted lines replace the obsolete assumption that the checked-in 291 manifest is the current terminal positive. The replacement proves it remains an exact 291 historical artifact and must refuse under the registered 296 route, while candidate-positive tests use a separately resealed structurally derived 296 manifest. Adapter identity, downgrade, tamper, extra-member, strict-subset, file-set, and structural-no-execution assertions remain.
- `test_s131_convergence.py`: 11 deleted lines advance only the terminal selector, helper population, and builder flag to 296, and add a second-build byte-equality assertion. Existing installed-runtime omission, extra-runtime, and byte-divergence controls remain.
- `test_member_contract.py` and `test_signed_release_convergence.py` remove no prior assertions.

No prior negative was deleted or weakened without an equal or stronger successor assertion. The missing executable-mode negative is an uncovered new requirement, not a removed historical assertion.

## Changed-set boundary

Audited source/documentation/index changes:

- `.github/write-enforcement/member_contract.py`
- `.github/write-enforcement/build_frozen_manifest.py`
- `.github/write-enforcement/signed_release_convergence.py`
- `.github/write-enforcement/signed_release_convergence_index.json`
- `.github/write-enforcement/SIGNED_RELEASE_CONVERGENCE.md`
- `.github/write-enforcement/SIGNED_RELEASE_CONVERGENCE_INDEX.md`
- six new `.github/write-enforcement/adapters/*.population-296-v1.json` files
- five modified focused test files
- the pre-existing Builder handback `artifacts/codex_handbacks/s232_govml_template_manifest_successor.md`

## Builder correction verification

The repair added
`validate_research_working_root_template_modes()` to the owning member contract
and invokes it through the existing shared builder/issuer validation path.
Historical population 291 returns before the new predicate, and unrelated
members retain their prior mode rules.

Fresh controls after repair:

- all five canonical template IDs pass at `100644`;
- every individual `100755` plant refuses through both
  `open_frozen_population()` and `issue_wea.verify_members()`;
- missing and symlink Git modes refuse;
- the real five-root manifest builder refuses a `100755` template before
  creating its output path;
- stdout and stderr remain empty in the opener/issuer mode refusals;
- the prior executable-mode probes no longer produce stale green under the
  corrected source.

Post-repair focused result: `199 passed, 1 skipped in 68.26s`.
Post-repair complete result: `457 passed, 1 skipped in 84.32s`.
Python compilation, convergence-index and six-adapter JSON parsing, and
`git diff --check` all passed. This closes the sole verifier defect; publication
does not authorize merge, freeze, tag, issue, install, or activation.

# WEA chain repair runbook — "generation 6" task, resolved as a generation-5 ruleset-basis refreeze

Prepared 2026-08-26 on branch `builder-arch/wea-generation-6-ruleset-refreeze`.
This branch prepares the repair; nothing here has been merged, tagged,
dispatched, or installed. Every claim below is re-derivable; commands and
file:line citations are given inline.

**Naming note.** The dispatching task assumed ruleset 19564990 had been
deleted and replaced by a different live ruleset, which would have required a
generation-6 member-contract cut. Section (a) shows that assumption is wrong:
19564990 is alive and was *modified*, not deleted. Under
`FREEZE_SEQUENCE.md` semantics ("`authority_generation` continues to identify
this member-contract generation", lines 50-53) the member contract is
unchanged, so the correct repair is a within-generation-5 manifest refreeze —
the same operation the repo performed ~30 times (see the
`rea-wea-generation-5-*` tag family). The branch/runbook keep the task's
"GENERATION_6" name; the artifact it ships is a generation-5 refreeze.
`member_contract.py` needs **zero edits**: `RULESET_ID = 19564990`
(`member_contract.py:15`) is still correct.

---

## (a) Diagnosis

1. **Symptom.** The issuer
   (`.github/workflows/issue-write-enforcement-attestation.yml`) last
   succeeded 2026-08-20T13:13Z (run 32373029378) and every renewal since
   fails in job `renew-wea`, step "Verify frozen bundle and issue", with
   `ValueError: live ruleset drift` raised at
   `.github/write-enforcement/issue_wea.py:330` (verified from run
   32641223608's log).
2. **The 404 story is a wrong-repo probe.** Ruleset 19564990 never lived on
   rexcoleman.dev. The issuer fetches it from **rexcoleman/newsletter**
   (workflow line 402: `gh api repos/rexcoleman/newsletter/rulesets/19564990`).
   `gh api repos/rexcoleman/rexcoleman.dev/rulesets/19564990` returns 404
   because the ruleset is not on that repo — it never was.
   `gh api repos/rexcoleman/newsletter/rulesets/19564990` returns 200 and
   `enforcement: active` today.
3. **Actual root cause: the live ruleset's normalized content drifted from
   the frozen digest.** `issue_wea.py:328-330` refuses when
   `sha256(canonical(normalize_ruleset(live)))` differs from the manifest's
   `normalized_ruleset_sha256`. Frozen (gen-4 and gen-5 manifests):
   `d4189cbf7b748e736f8e6d6ff2b2dd0bcf892c3bff671885e4d3ea789ec6f97d`.
   Live today:
   `324dbfc7014c49a137cf089da7762bd41761112b9e9fbd91d09f68de9963db8e`.
   Two normalized-field differences (raw captures in
   `evidence/s_gen5_ruleset_refreeze_20260826/`):
   - `rules[pull_request].parameters` now carries
     `"require_extra_approval_for_unattributed_changes": true` — a
     pull-request-rule parameter GitHub added to API responses; the ruleset
     history shows **no ruleset edit between 2026-08-18T02:42Z and
     2026-08-23T21:28Z**, yet the drift began between the Aug-20 success and
     the first Aug-21 failure, so this field's appearance/serialization is a
     GitHub-side change, not an owner edit. The same field now also appears
     on rexcoleman.dev's ruleset 19768000.
   - `bypass_actors` changed from `[]` to
     `[{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]`
     (repository-admin always-bypass). Ruleset history version 47394538 shows
     this was made 2026-08-23T21:28:12Z by user id 89108541, which is
     `rexcoleman` (`gh api user`). ⚠ **Owner ratification item:** this
     weakens newsletter-main protection (admin can bypass the PR +
     status-check rules). If Rex wants it reverted, revert it in the GitHub
     UI FIRST and rebuild the manifest (step (c)-0 below) so the frozen
     digest matches whatever shape he ratifies. The prepared manifest
     freezes the live shape **as-is, including the admin bypass**.
4. **Secondary failure (scheduler).** Since 2026-08-24 the renewal scheduler
   (`renew-write-enforcement-attestation.yml`) fails before dispatching:
   `REFUSED RENEWAL_ISSUANCE_ARTIFACT_IDENTITY_REFUSED: run_id=30136397395`
   (verified from scheduler run 33008579334). Its resolve step iterates the
   newest 100 successful tagged issuer runs and hard-refuses on the first one
   whose `rea-write-enforcement-attestation-<run_id>` artifact is listed but
   `expired: true` (workflow lines 141-153). Because issuance stopped on
   Aug 20, old runs stopped aging out of the top-100 window and their 30-day
   artifact retention began expiring inside it. **A new successful issuance
   does NOT clear this by itself.** The scheduler must treat expired listing
   rows as tombstones and continue to the newest live identity-bound artifact
   (step 6 below). No artifact-record deletion is part of the repair. As of
   2026-08-26: runs 30136397395, 30116484408, 30115223596 (artifacts
   8613163935, 8605648354, 8605316797).
5. **Local install state.** The installed authority at
   `~/.local/state/rea_enforcement/remote_wea/` is epoch 71, issued
   2026-08-15T18:50:21Z from run 31902192746, expired 2026-08-16T18:50:21Z.
   Probe today: `python3 write_integrity/attestation/wea_verifier.py status`
   (from `~/research_enforcement_activation`) → exit 3, `WEA_EXPIRED`.
   The newest issued authority is **epoch 90**, run 32373029378 (artifact
   live until 2026-09-19T13:13Z), and is the predecessor for the repair
   issuance.

## (b) Ruleset identity comparison

What frozen ruleset 19564990 was (raw bytes preserved at
`tests/evidence/s149_band3_freeze/raw/rulesets/newsletter.19564990.json`;
its `normalize_ruleset` digest reproduces the frozen
`d4189cbf…` exactly):

| field | frozen 19564990 |
|---|---|
| name | `newsletter-main-integrity` |
| source | `rexcoleman/newsletter` |
| target / enforcement | `branch` / `active` |
| conditions | `refs/heads/main` |
| rules | `deletion`, `non_fast_forward`, `pull_request` (1 approving review, last-push approval, thread resolution), `required_status_checks` (`newsletter-remote-integrity / newsletter-remote-integrity`, integration 15368, strict) |
| bypass_actors | `[]` |

The two rexcoleman.dev live rulesets, fetched 2026-08-26:

| | 19623489 `rea-wea-generation-tags` | 19768000 `rexcoleman-dev-main-integrity` |
|---|---|---|
| target | `tag` (`refs/tags/rea-wea-generation-*`) | `branch` (`refs/heads/main`) |
| rules | deletion, non_fast_forward | deletion, non_fast_forward, pull_request |
| protects | WEA generation tags on rexcoleman.dev | rexcoleman.dev main |

**Neither covers what 19564990 enforces** — newsletter `main` publication
integrity with the `newsletter-remote-integrity` required status check.
No recreation is needed either: **the functional (and literal) successor of
19564990 is 19564990 itself**, still active on rexcoleman/newsletter. The
frozen basis, not the ruleset, is what must move.

## (c) Remaining steps, in order

Machine steps are kc/coach-executable with the rexcoleman-authenticated `gh`.
Rex's only mandatory action is step 4's environment approval.

**0. (Conditional — only if Rex reverts the Aug-23 bypass_actors edit.)**
   Re-fetch the live ruleset and rebuild the manifest exactly as this branch
   did, then replace the manifest commit:

   ```
   gh api repos/rexcoleman/newsletter/rulesets/19564990 > /tmp/ruleset.json
   # five roots checked out clean at the commits recorded in the current
   # generation-5 manifest (they are unchanged by this repair):
   #   research_enforcement_activation @ 0fba259c2cc2a18f23c418ced92bdb1a5f236455
   #   govML                           @ 5bd9f34b40162fc3e161d2d50647e9ae6297c5a6
   #   Moonshots_Career_Thesis(_v2)    @ ec50dc601bbd422f5418a3152ff444378f3ab576
   #   newsletter                      @ 8419fb35249ca8866df600c428b2a8571f523946
   #   rexcoleman.dev                  @ d5ff595077536583794dffb36715958778919ecb
   PYTHONPATH=<rexdev>/.github/write-enforcement python3 \
     <rexdev>/.github/write-enforcement/build_frozen_manifest.py \
     --successor-ci-materialization --ruleset-json /tmp/ruleset.json \
     --output frozen_bundle_manifest.generation-5.json \
     --root-research-enforcement-activation <rea_root> \
     --root-govml <govml_root> \
     --root-moonshots-career-thesis-v2 <moonshots_root> \
     --root-newsletter <newsletter_root> \
     --root-rexcoleman-dev <rexdev_at_d5ff595>
   ```

   Skip this step entirely if the live shape is ratified as-is: the manifest
   on this branch was built by that exact procedure and verified
   deterministic (two byte-identical builds,
   sha256 `7b2337ff83731eba15a1ed8675e7df855a34467d8a00ecf5f39689c31561932b`).

**1. PR and merge.** Open a PR from
   `builder-arch/wea-generation-6-ruleset-refreeze` into `main` and merge it
   **with a merge commit — never squash or rebase** (the tag in step 3
   targets the pushed manifest-only commit sha, which must remain reachable
   from `main`). rexcoleman.dev main's ruleset 19768000 requires a PR but 0
   approving reviews, so the kc's session can merge. Optional post-hoc audit:
   dispatch `independent-second-principal-review.yml` (mode `preflight`,
   repository `rexcoleman/rexcoleman.dev`, the PR number, the PR head sha,
   the canonical PR file-set sha, `expected_manifest_sha256=7b2337ff8373…932b`).

**2. Verify the manifest-only commit.** The branch tip commit changes exactly
   `.github/write-enforcement/frozen_bundle_manifest.generation-5.json`
   (required by `GENERATION_5_OWNER_RUNBOOK.md` lines 11-13). Confirm:
   `git show --stat <manifest_commit>` lists that one file; its parent
   carries this runbook + evidence.

**3. Create the annotated generation tag** on the manifest-only commit
   (NOT on the merge commit):

   ```
   ISSUER_SHA=<40-hex sha of the manifest-only commit>
   ISSUER_TAG="rea-wea-generation-5-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"
   git tag -a "$ISSUER_TAG" -m "generation-5 ruleset-basis refreeze" "$ISSUER_SHA"
   git push origin "$ISSUER_TAG"
   ```

   Ruleset 19623489 permits tag creation (it forbids only deletion and
   non-fast-forward moves). Never reuse or move an existing
   `rea-wea-generation-*` tag.

**4. Dispatch the issuance — mode `capability_change_existing_secret`.**
   The downstream bundle-read secret is already installed and unchanged, so
   the seal-free capability-change mode applies (workflow lines 10-13; the
   no-seal preflight at lines 256-270 requires all seal inputs empty).
   Predecessor = the newest issued authority (epoch 90):

   ```
   gh workflow run issue-write-enforcement-attestation.yml \
     --repo rexcoleman/rexcoleman.dev \
     --ref "refs/tags/$ISSUER_TAG" \
     -f mode=capability_change_existing_secret \
     -f predecessor_run_id=32373029378 \
     -f predecessor_wea_sha256=06c89fd5083a5aaa205af98250a73ec11aa8d3b41b7c0362c4c1e65906678d5e
   ```

   All other inputs (downstream_*, sealed_*) stay **empty** — the workflow
   refuses this mode if any is set. Input provenance:
   - `predecessor_run_id` 32373029378 = newest `completed:success`
     `workflow_dispatch` issuer run (2026-08-20T13:13Z); its
     `rea-write-enforcement-attestation-32373029378` artifact is unexpired
     until 2026-09-19T13:13Z, which the preflight requires.
   - `predecessor_wea_sha256` = sha256 of `write_enforcement_attestation.json`
     inside that artifact (epoch 90). Re-derive:
     `gh run download 32373029378 -R rexcoleman/rexcoleman.dev -n rea-write-enforcement-attestation-32373029378 -D /tmp/pred && sha256sum /tmp/pred/write_enforcement_attestation.json`.
   - **If dispatch happens after 2026-09-19** the epoch-90 artifact will have
     expired; re-resolve both values with the two commands above against the
     then-newest successful run (they are the only dispatch-time-dependent
     inputs).
   - The installed-but-stale epoch-71 pair (run 31902192746, sha256
     `f8c8b6d8fdc25f8c313128b38be77a3a2f3d3abdce8938c69619509d57b10aa9`)
     also passes preflight until 2026-09-14 but would fork the epoch chain
     back to 72; use epoch 90.

**5. Rex's single approval — the environment gate.** Jobs
   `preflight-sealed-transfer`→`issue-wea` run; `issue-wea` declares
   `environment: rea-write-enforcement-issuer`, whose sole protection rule is
   `required_reviewers: [rexcoleman]` (verified via
   `gh api repos/rexcoleman/rexcoleman.dev/environments`). Rex will see the
   run at
   `https://github.com/rexcoleman/rexcoleman.dev/actions/workflows/issue-write-enforcement-attestation.yml`
   waiting with a **"Review pending deployments"** banner; he clicks it,
   ticks `rea-write-enforcement-issuer`, and presses **Approve and deploy**.
   What he is approving: issuance of authority epoch 91 over the refrozen
   ruleset basis — including, if step 0 was skipped, the admin-bypass
   `bypass_actors` entry he added on 2026-08-23. After approval the job
   verifies all 259 frozen members, refetches the live ruleset (drift check
   now passes), signs, self-verifies on the runner, uploads
   `rea-write-enforcement-attestation-<new_run_id>`, and appends the public
   packet.

**6. Unpoison the renewal scheduler at the resolver.** Land the registered
   scheduler repair that filters the matching artifact population to
   `expired == false` before uniqueness and identity checks. An expired row is
   skipped; exactly one live identity-bound row is accepted; multiple live
   rows or a live identity mismatch still refuse. The focused workflow suite
   proves all three polarities. Do not delete any GitHub artifact record to
   satisfy this read path. Then confirm the scheduler recovers:
   `gh workflow run renew-write-enforcement-attestation.yml -R rexcoleman/rexcoleman.dev`
   and watch it reach `RENEWAL_RUN_STATE … completed:success` — it must now
   resolve the step-4 run's tag and the renew-mode issuance must pass the
   ruleset check with the refrozen digest.

## (e) Resync the local install on gios-dev

`~/.local/state/rea_enforcement/remote_wea/` is the state root every consumer
reads (`wea_verifier.py:28`, govML `install_write_enforcement.py:33`,
Moonshots `scaffold_research_project.py` line ~55 via `REA_WEA_STATE_ROOT`).
The `runtime_mount.py` in that directory is a *member of the packet* (the
write-integrity route mount installed alongside), not the sync tool; the sync
is: preserve, then replace with the newest issuance artifact, then verify.

```
cd ~/research_enforcement_activation
python3 write_integrity/attestation/tools/preserve_remote_wea.py \
  --snapshot-dir write_integrity/attestation/evidence/preserve_remote_wea_$(date -u +%Y%m%dT%H%M%SZ)
NEW_RUN=<run id of the step-4/step-6 issuance>
gh run download "$NEW_RUN" -R rexcoleman/rexcoleman.dev \
  -n "rea-write-enforcement-attestation-$NEW_RUN" -D /tmp/wea_new
( cd /tmp/wea_new && sha256sum -c SHA256SUMS )
rm -f ~/.local/state/rea_enforcement/remote_wea/*
cp /tmp/wea_new/* ~/.local/state/rea_enforcement/remote_wea/
chmod 755 ~/.local/state/rea_enforcement/remote_wea/hybrid_capability_provider \
          ~/.local/state/rea_enforcement/remote_wea/runtime_mount.py
```

Because the authority lives 24 hours, prefer resyncing from the **latest
renewal run's** artifact (same download shape, newest run id) whenever the
resync happens more than a day after issuance. Also refresh any project-local
`write_integrity/remote_wea/` copies the same way where a project pins one
(known prior divergence: DECISION_LOG.md L5127).

## (f) Verification

```
cd ~/research_enforcement_activation
python3 write_integrity/attestation/wea_verifier.py status; echo "RC=$?"
```

Required: `RC=0` and the JSON reports the new epoch with
`"state": "ENFORCING"` (today this exits 3 with `WEA_EXPIRED`). That is the
scaffolder's authentication path (`scaffold_research_project.py`
`_signed_bundle_identity()` reads the same state root); a govML-side check of
the same substrate is `python3 ~/ml-governance-templates/templates/build/enforcement/write_enforcement_state.py`
run from an installed project. Finally confirm the next two scheduled
renewals (cron `17 */6 * * *`) conclude `success` with no owner action.

---

### What was verified on this branch, and how

- Rebuilt manifest changes exactly two fields vs the shipped generation-5
  manifest — `normalized_ruleset_sha256` (`d4189cbf…` → `324dbfc7…`) and
  `manifest_digest` (`51364d20…` → `d84eb68a…`); all 259 member rows are
  byte-identical. Two independent builds from the five frozen roots were
  byte-identical (manifest sha256 `7b2337ff8373…932b`).
- Full write-enforcement suite at this branch: `pytest`
  `.github/write-enforcement/tests/` → **494 passed, 1 skipped**; the CI
  focused set (`signed-release-convergence.yml` lines 63-71) → 228 passed,
  1 skipped.
- No code, workflow, secret, environment, ruleset, or tag was changed by this
  branch. The only tracked changes are this runbook, the raw ruleset
  evidence, and the rebuilt manifest.

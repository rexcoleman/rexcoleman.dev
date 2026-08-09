# REA s149 Band 3 convergence and generation-4 freeze

Status: COMPLETE for the bounded Band 3 deliverable. The five signed-bundle repositories were selected from freshly fetched remote refs, the registered rexcoleman.dev builder emitted generation 4 once, the manifest-only freeze was merged, and every credited measurement below ran only after that merge. No issuance, tag, installation, arming, approval, or owner action was attempted.

## Authority and scope

- Parent authority: kc-63 final superseding single-shot directive to downstream Coach s149.
- Worker role: foreground general-purpose Builder/Executor for Band 3 only.
- Subject: the generation-4 signed bundle spanning `rexcoleman/govML`, `rexcoleman/research_enforcement_activation`, `rexcoleman/Moonshots_Career_Thesis`, `rexcoleman/newsletter`, and `rexcoleman/rexcoleman.dev`.
- Manual acts performed before measurement: fresh clones were fetched; each candidate was detached at its fetched `origin/*` ref; the registered builder was invoked once; the resulting manifest-only commit was published by PR; the post-freeze controls were then run from the merged remote state. No working-tree bytes were treated as authority.
- Explicit boundary: this record does not establish issuance, installation, arming, default-on enforcement, R1-R9, or blind-corpus performance.

## Reality versus intent

| Requirement | Reality status | Exact evidence |
|---|---|---|
| Read exact publication policy | measured | `raw/rulesets/*.postfreeze.json`; all API exits were 0 |
| Select clean fetched remote heads | measured | frozen manifest plus `raw/freeze_builder.stdout.txt`; pre-build status files were zero bytes |
| Bands 1/2 commits precede selected heads | measured | `raw/ancestry/*.txt`; every `ancestor_rc=0` |
| Build generation 4 exactly once with registered builder | measured | `raw/freeze_builder.stdout.txt` has 229 `REMOTE_REACHABLE` rows; stderr is empty; the only emitted production manifest was committed as `1ec2ab05c141abdfb22d7d46453d6bf52fc1dce8` |
| Manifest/member set closes exactly | measured | `raw/postfreeze_manifest_byte_verifier.stdout.txt`, exit 0, 229 exact members and exact bytes |
| Honest and refusal polarities | measured | `raw/postfreeze_focused_polarities.stdout.txt`, 11/11; `raw/postfreeze_real_seed_construction.stdout.txt`, true exit 0 with genuine-complete exit 0, under-build exit 1, and 19-byte gutted named surface exit 1 |
| Full freeze/issuer suite | measured | `raw/postfreeze_full_wea_tests.stdout.txt`, 315/315, true exit 0 |
| Remote reachability after landing | measured | `raw/postfreeze_remote/*`, all five exact SHAs observed at exit 0 |
| Freeze strict ancestor of later evidence | measured after the first evidence commit | `raw/strict_ancestry_to_evidence.txt` is added by the follow-up evidence commit |
| Issue, tag, install, arm | not-established, deliberately out of Band 3 | prohibited by dispatch; no action taken |

## Exact selected population

| Logical repository | Selected fetched remote commit | Branch authority |
|---|---|---|
| `govML` | `5cef85af1053a72d2e52593b806e460662f143b2` | `origin/main` |
| `research_enforcement_activation` | `5d4eea5d9e4b22f68bd14efbec2f23349b28567b` | `origin/master` |
| `Moonshots_Career_Thesis_v2` | `7b67fb27603dc7ef4b5f696a901cb80ec2a5af4c` | `origin/main` |
| `newsletter` | `8419fb35249ca8866df600c428b2a8571f523946` | `origin/main` |
| `rexcoleman.dev` | `09c9675ce74d17db9c908f56445eee03f42400f0` | `origin/main` |

The manifest has 229 unique member IDs, manifest digest `63fd6006092d46114ef56a094528aceea2aa002329a291bb5aa7fc3811f7add4`, file SHA-256 `02d6c31007800caa4bcc834c94dc31a26667785088228655b1a0a59078f6e317`, and normalized newsletter ruleset digest `d4189cbf7b748e736f8e6d6ff2b2dd0bcf892c3bff671885e4d3ea789ec6f97d`.

## Input ancestry re-derived

Every listed implementation/evidence commit returned true exit 0 under `git merge-base --is-ancestor <commit> <selected-head>`:

- govML Band 1a implementation `bd5091caea7d360e2105463a0a3ebddbdff75aaa` and evidence `de6d33d9ca480d734d98373db8b998845339bc8c`;
- govML Band 2a implementation `56b2c192e6389156dc50b0d683f5f16f4724f41f` and evidence `cc7e37c8074f37d60e7a90c1095f99ebfe96bd98`;
- REA provider/status fixes `680e5f7b785723097fa6e75287f9601092fd7d6d` and `c3a7d1f5def497b057ba212321f6b07a4759bc2e`;
- REA Band 2c implementation `75a58d1131fa9e65823a5789d783e9f86fec498e` and evidence `4267bb35d41d7e76c6c50fa3553947d9c62fe565`;
- REA Band 2b implementation `4873ee933cae1d9fbb2cbd1be426e3d084a60992` and rules evidence `f9b5be040283599ab87bf9cf6a917285a1bd3219`;
- REA Band 2d evidence/closure commit `f80d5d05ca3caa24860d70e403990399419dc509`.

## Ruleset and publication decision

The exact live rulesets were read directly, not inferred from checks:

- govML ruleset 20150035: PR, zero approvals, required `artifact-integrity-exact-commit`, no bypass actors.
- REA ruleset 19911466: PR, zero approvals, no required status checks, no bypass actors.
- Moonshots main branch protection: strict `artifact-integrity-exact-commit`; no repository ruleset was returned.
- newsletter ruleset 19564990: one approval, last-push approval, required `newsletter-remote-integrity / newsletter-remote-integrity`, no bypass actors.
- rexcoleman.dev main ruleset 19768000: PR, zero approvals, no required status checks, no bypass actors. Tag ruleset 19623489 was read but no tag was created.

Only rexcoleman.dev changed in Band 3. Manifest-only freeze commit `1ec2ab05c141abdfb22d7d46453d6bf52fc1dce8` was merged by PR #37 at merge commit `472ae1c45c0b54b272d06d3c642931158d5efdee`. PR state was `MERGED`; there were zero checks and zero reviews, consistent with the exact active main ruleset rather than an inferred gate.

## Both polarities and true exits

The credited post-freeze suite returned true exit 0 with 315 passing tests. A focused run returned true exit 0 with 11 passing controls, including:

- honest committed-member reading;
- refusal on a dirty bound member;
- honest exact five-root manifest construction;
- current manifest admission;
- refusal at one member below and one member above the closed contract;
- issuer refusal on workflow-byte drift;
- hosted verifier refusal on four carried-member-copy drift plants.

The canonical govML construction gate was also run against a clean clone of REA commit `5d4eea5d...` and its real `RESEARCH_SEED.md`. It admitted `genuine_complete` at exit 0 and refused the `under_build` plant and the 19-byte no-op gutting of seed-named `composite_quality_block_A1` at exit 1. The outer self-test returned true exit 0 and `all_distinguished=True`. This is a polarity check of the construction gate, not a claim that Band 5 has run.

## Facts, inference, and gaps

Facts are the raw exits, exact SHAs, exact ruleset JSON, manifest bytes, GitHub PR state, and test results stored here. The inference is limited to: because the freeze commit is an ancestor of the evidence commits and the manifest pins immutable, remotely reachable commits, these post-freeze controls measure the landed frozen population rather than an unfrozen working tree.

No Band 2 item was cut in this worker's input: the selected heads contain the supplied Band 1 and Band 2 implementation/evidence commits. This report does not independently re-adjudicate the semantic sufficiency of every prior band; it re-derives their ancestry and freezes their landed bytes.

## GPL-47: What This Does NOT Prove

This does not prove that an issuance approval exists or will be consumed, that a signed packet is installed, that the write side is armed, that four scaffold types block by default, that R1-R9 pass on live surfaces, that a protected newsletter faithful merge has an independent approval, or that any blind-corpus metric has been measured. It also does not treat the construction self-test as Band 5 completion. Those remain downstream of the owner package and arming sequence.

## Repository hygiene

All implementation repositories were clean at selection. Test-created caches were removed before commits. The freeze commit changed only `.github/write-enforcement/frozen_bundle_manifest.generation-4.json`. This evidence lives under a tracked `tests/evidence/` path, not ignored `build/` or `outputs/*.json`.

# Hosted external-judge approving principal: one-time owner package

## Status and boundary

This package is staged for Coach review. It is not an authorization to run it.
It does not issue an authority, spend a nonce, disclose a subject, fire F2/F3,
freeze a manifest, reissue a WEA, or activate production. The only genuinely
owner-held capabilities are the one-time GitHub and Azure authentications used
to establish the protected environment and the fixed root-owned public half.

The source owner row is
`.github/write-enforcement/rea_s169_external_judge_principal_owner_row.txt`.
It is deliberately **not deliverable** from this review worktree: the payload
must first land on protected `rexcoleman.dev` `origin/main`, then the registered
delivery compiler must deploy a digest-bound durable package and emit the one
short home-path opener. No deep source row or opener is owner-ready in this
staged set. After that final compilation, the row drives the complete setup through
`setup_external_judge_hosted_principal.py --apply`. There is no second command
file and no per-issuance owner step. The row is for `gios-dev`, the Azure VM,
not a MacBook or the Mac Mini. Every path in it is absolute, so the working
directory does not matter.

## One-time sequence driven by the row

1. The wrapper proves hostname `gios-dev`, uid 1000, and that its complete
   transitive rex payload is a clean byte-for-byte checkout of the exact
   protected `origin/main` commit. The Python tool repeats that binding before
   any GitHub or Azure mutation. It also proves a
   govML `origin/main` issuer containing the hosted exact-byte, TTL, and secret
   bindings. Expected result: `READY_FOR_ONE_TIME_SETUP`, or an idempotent
   `COMPLETE` if setup already matches exactly.
2. The wrapper authenticates the owner to GitHub once if the existing `gh`
   session is absent or expired. It creates only the dedicated
   `govml-external-judge-approver` environment and refuses any required
   reviewer or wait-timer protection that would create a per-issuance human
   step.
   Every configuration sub-boundary is attributed to the environment id
   returned by the create call. Variables must form the exact package-owned
   prefix and the secret set must be empty or exactly the one package secret;
   two identical reads precede any partial-state deletion. An unreadable list,
   foreign row, concurrent environment id, or protection drift refuses without
   deletion.
3. It generates one Ed25519 keypair in process memory. The private half is sent
   over standard input to the dedicated environment secret and is never
   written to disk, printed, placed in an argument, or recorded in evidence.
   The environment receives the public-key digest plus the exact govML issuer
   commit and source digest as non-secret variables.
4. The wrapper authenticates the owner to Azure once if required, derives the
   current VM identity from the Azure Instance Metadata Service, and uses Azure
   VM Run Command to atomically link a staged public half at the verifier's
   fixed path as `root:root` mode `0644`. The measured predecessor is a regular
   `nobody:nogroup` (`65534:65534`) mode `0644`, 113-byte file with SHA-256
   `69a974bc7dd189c6ee56d105a2abcf35ddba0e039b070f153ad82bd22806b928`;
   the same privileged transition binds it exactly, hard-links a protected
   backup, and atomically replaces it. Any predecessor drift or an unexpected
   target at execution time refuses. No Mac or BCS route is involved.
5. It re-reads the fixed public file, proves ownership, mode, and exact digest,
   marks the protected environment complete, and re-runs the whole preflight.
   Expected final line: `HOSTED_PRINCIPAL_SETUP_COMPLETE` with
   `per_issuance_human_steps` equal to zero. Estimated duration is 5-10 minutes,
   dominated by the two one-time browser authentications.

Afterward a machine dispatches exact non-secret create-request bytes to the
registered workflow. The workflow signs with the protected environment secret
and emits a public authority plus authenticated receipt. The project client
requires the selected run's `head_sha` and public receipt `workflow_commit` to
equal the exact protected-main commit resolved before dispatch, then
authenticates that packet against the fixed host public key. The ordinary
verifier then binds project root, relative path, subject digest, provider,
model, purpose, expiry no later than 900 seconds, principal, signature, and
nonce, and atomically spends the nonce with exclusive creation. Rex performs
no approval, click, copy, token handoff, or other action per issuance.
The client resolves request/output paths before dispatch, refuses aliases and
pre-existing or symlink targets, and uses no-clobber links. It publishes the
non-authorizing receipt first and the signed authority last as the pair's commit
marker. If authority publication fails, it removes only the exact inode and
digest of the receipt created by that invocation; drift refuses cleanup while
still leaving no invocation-created authority.

## Measured troubleshooting and recovery

| observed result | meaning | recovery driven by the same row | rehearsed evidence |
|---|---|---|---|
| GitHub authentication prompt | existing `gh` token is absent or expired | finish the one-time web authentication; the wrapper resumes without exposing the token | live preflight observed expired auth; static wrapper contract test passes |
| Azure device-code prompt | the dedicated writable Azure CLI session is absent | finish the one-time device-code authentication; the wrapper resumes and targets only metadata-derived `gios-dev` | wrapper source test binds device-code and metadata route |
| planted public-key installation failure | GitHub pending state exists but the root install did not complete | wrapper deletes the dedicated environment before refusing; rerun the same row | `test_transition_failures_run_recovery[install]` passes |
| planted completion-marker failure | secret and public placement completed but final commit of setup state failed | wrapper re-reads and deletes only the exact package-owned pending environment, then removes only the regular root-owned non-writable public file with the expected digest | `test_transition_failures_run_recovery[mark]` passes |
| interrupted pending setup | a prior process ended between protected-secret creation and completion | wrapper refuses a mismatched public file, re-reads the exact pending remote state twice, deletes that state, removes only its digest-matching public file, and starts a fresh transition | pending, mismatch, and remote-drift planted tests pass |
| target appears after preflight | another file occupies the fixed path before root install | atomic no-clobber link fails; remote pending state is rolled back and the occupying file is unchanged | `test_post_preflight_target_appearance_never_overwrites_unrelated_key` passes |
| measured predecessor plus planted later failure | the real nobody-owned predecessor was replaced, then setup failed before the complete marker | exact pending remote state is deleted and the privileged rollback atomically restores predecessor bytes, uid, gid, and mode | `test_measured_predecessor_is_restored_exactly_on_later_failure` passes |
| final check fails after complete marker | GitHub already holds exact complete state and the fixed file is the matching new root-owned key | the complete marker is the commit boundary; no destructive pending rollback runs, and rerun is idempotent | `test_final_postcheck_failure_after_marker_keeps_exact_complete_commit` passes |
| rex payload or hosted workflow drifts | reviewed local bytes are no longer the landed protected-main package, or a dispatched run uses another commit | hard refusal before setup mutation or artifact credit | local-drift and wrong-head/receipt-commit planted tests pass |
| configuration fails after environment creation or any variable/secret boundary | an attributable exact prefix exists | twice-read exact partial state is deleted; unreadable or foreign state refuses without DELETE | six-boundary, concurrent-appearance, and list-failure planted tests pass |
| client output aliases, pre-exists, or appears after preflight | an input/output identity is ambiguous or unrelated bytes occupy a target | refuse before dispatch or no-clobber at publication; authority remains unpublished and unrelated bytes remain | alias, preexisting, authority-appearance, and cleanup-drift planted tests pass |
| unknown pre-existing environment or public file | state cannot be attributed safely to this package | hard refusal; no overwrite and no key rotation | pre-existing-state branch in `apply()` |
| environment has required reviewers | a human would be required for every issuance | hard design refusal `PER_ISSUANCE_HUMAN_REVIEW_REFUSED`; remove that design outside this package before retry | workflow/setup focused tests |

The public-file removal recovery requires, inside one root command, the exact
expected digest, regular-file type, `root:root`, non-writable mode, stable inode,
and a second exact digest immediately before unlink. The environment deletion
recovery requires two identical reads of the exact package-owned pending state;
concurrent drift hard-refuses without deletion. A
successful pre-existing setup is idempotent and is never rotated or
overwritten. Anything else is refused rather than guessed.

## Package audit

The source row is one physical ASCII line plus one final newline and contains no
compound separator, but it remains non-deliverable until protected-main landing
and registered final compilation. The checked wrapper runs its own preflight, implements the
whole one-time arc, authenticates both owner-only surfaces inside that arc,
keeps the private key in memory, verifies the final posture, and contains
tested rollback after each mutating boundary. The package is `NOT SAFE to
paste back` because authentication UI output can contain account metadata,
although the wrapper itself never prints a credential.

## GPL-47: What This Does NOT Prove

This staged package does not prove the owner has run it, that the GitHub
environment or secret exists, that the fixed public key has been replaced,
that a hosted workflow has run, that a real authority has been issued, that a
real subject has been read or disclosed, that F2/F3 is clear, or that any
production activation is authorized. Scratch signatures and fake-backend
rollback tests prove mechanism and refusal behavior only.

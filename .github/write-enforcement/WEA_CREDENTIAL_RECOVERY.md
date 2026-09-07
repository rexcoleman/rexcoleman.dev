# WEA credential recovery rail

## Purpose and boundary

The s212 rail restores the complete credential substrate required by the
generation-5 issuance, renewal, and hosted external-judge paths. It is one
no-argument owner row on `gios-dev`. Its Python apply path binds and reruns
`--preflight` before mutation, probes the currently stored credentials on the
GitHub-hosted environments before asking Rex for any replacement, and then
converges the three environments and the fixed verifier public key.

The rail does **not** fire F3, issue an authority, freeze a bundle, create a
tag, or touch the Mac. Credential readiness is its only terminal property.
The immutable generation tag still lacks the s210 GitHub App wiring; landing
this recovery rail does not change that tag and does not make an ordinary
`origin/main` import a member of the frozen signed root.

An ordinary Python import of a module inside the ignored signed member root can
write `__pycache__` and make the root fail its closed-set check even while Git
reports no change. The wrapper and hosted workflow therefore set
`PYTHONDONTWRITEBYTECODE=1`; tests use the same setting. This is an execution
precondition, not repository cleanliness inferred from `git status`.

## Whole-arc order

1. Prove `gios-dev`, `azureuser`, a real TTY, exact protected-main source
   bytes, SHA-256 digests of every required local tool, the pinned current
   minter, the exact policies of issuer, renewal, and
   approver environments, the landed govML issuer, and set/remove capability
   using one uniquely named throwaway secret at each locus.
2. Dispatch the non-disclosing hosted probe. The issuer environment retains
   its reviewer protection, so the same row prints the exact run URL and waits
   while Rex approves that deployment. Probe output contains status words only.
3. Reuse the existing `REA_BUNDLE_READ_TOKEN` and
   `REA_RULESET_READ_TOKEN` when both issuer and renewal copies authenticate
   against the exact four-repository bundle plus newsletter ruleset. Only if
   that server-side test fails, ask through hidden TTY prompts for both
   replacements. Both values authenticate before either is placed.
4. Reuse a complete local GitHub App pair when the pinned minter validates it.
   A partial pair refuses. Otherwise the same row directs Rex through creation
   of an App owned by `rexcoleman`, Contents read-only and no other permission,
   installed on exactly `govML`, `research_enforcement_activation`,
   `Moonshots_Career_Thesis`, `newsletter`, and `rexcoleman.dev`. The pinned
   minter must mint and read all five before the pair is atomically added to
   the mode-`0600` local env. A newly supplied PEM must itself be a regular,
   non-symlink file owned by `azureuser` at mode `0600`.
5. Place the App pair in issuer, renewal, and approver. Generate the approver
   Ed25519 key in process memory, place its private half as the approver secret,
   place the public digest and exact govML issuer commit/digest as variables,
   and use Azure VM Run Command to replace the root-owned public key with an
   exact predecessor backup and rollback path. The broken local sudo route is
   never used.
6. Repeat the hosted probe. Completion requires the App route and legacy pair
   to pass at issuer and renewal, and the App route plus principal package to
   pass at approver.

If a PAT must be minted, the rail directs Rex to a classic PAT with `repo`
scope and **No expiration**. Fine-grained tokens are deliberately disfavored
because GitHub caps them at 366 days, recreating the expiry incident.

## Failure and recovery

- A partial local App pair refuses. Downstream credential selection also
  refuses partial pairs rather than falling back to a PAT; the recovery rail
  may replace a partial hosted pair only with one complete validated pair.
- A failed second PAT authentication occurs before any write.
- GitHub never exposes an old secret value. Therefore a partially failed PAT
  replacement is forward-completed from the two already authenticated values,
  not falsely described as byte rollback.
- The same write-only constraint applies to App secrets. A partially failed
  App placement is forward-completed across all three environments from the
  already validated complete pair.
- A local App env change is atomic and its predecessor bytes are retained in
  memory until the final hosted postcondition passes; a later failure restores
  those bytes or removes the newly created file.
- Approver principal variables and secret are deleted on a pre-commit failure.
  If the Azure public-key replacement occurred, its exact root-owned predecessor
  is restored through the same Azure mechanism.
- Every external subprocess has a timeout. The hosted probe has a 15-minute
  ceiling, enough for the one required issuer deployment approval; timeout is
  a refusal, not permission to continue.
- Changed protected-main source, wrong repository set, unexpected environment
  policy, non-TTY use, or an unreadable postcondition refuses.

## Owner interaction

The only capabilities the Coach cannot perform are Rex's GitHub browser acts,
hidden PAT entry if reuse fails, and the one-time Azure device-code login if
the existing Azure session is absent. All hops remain inside one running row.
The row may be re-run idempotently after a browser refusal or authentication
timeout.

The output is **NOT SAFE to paste back** because browser/device authentication
diagnostics can contain account metadata, even though the rail never emits a
credential value or digest.

## Tests and registration

Focused tests live in
`.github/write-enforcement/tests/test_s212_wea_credential_recovery.py`. The
credential probe is `.github/workflows/probe-wea-credentials.yml`. The
cross-generation inventory registers the source rail, focused tests, and
workflow with tested hermetic, identity, refusal, poststate, resume, and
evidence properties.

## What this does not prove

Repository tests and an adversarial dry run prove transaction structure and
refusal polarity. They do not prove Rex has completed the browser steps, that
the live environments contain the new credentials, that an external-judge
authority exists, or that any write-enforcement issuance has occurred. Those
facts exist only after the owner runs the deployed row and the agent performs
the named postchecks.

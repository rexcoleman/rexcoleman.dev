# Generation-5 WEA release runbook

Generation 5 is a successor authority over the exact population closed by the
selected adapter in `signed_release_convergence_index.json`. It adds
`ci-enforcement-materializer`, the protected downstream
bundle-secret transition, and the public attestation packet publisher.
It never edits or reuses the generation-4 manifest.

## Frozen identity

The release feature commit must be created through the normal hook and its pull
request must change exactly this ordered two-file set:

1. `.github/write-enforcement/frozen_bundle_manifest.generation-5.json`;
2. `.governance/pre_commit_boundary.json`.

The receipt is not an extra semantic release change. The normal pre-commit hook
generates its canonical bytes, binds its parent to the pull-request base, and
records the manifest as the sole semantic changed path. The callable independent
reviewer re-fetches both files at the exact head and verifies the receipt Git
blob, parent, changed-path count and digest, the whole two-file-set digest, and
the manifest SHA-256. A manifest-only file set or a hand-written receipt refuses.

The annotated protected tag is derived as `rea-wea-generation-5-` plus the first
12 lowercase hexadecimal characters of that reviewed feature commit. The tag
must peel exactly once to that commit. The protected-main merge may have a later
commit identity, but its tree must be identical to the reviewed feature tree.
The manifest must report generation 5, the exact registered adapter population,
the registered successor materializer subject, the registered protected
downstream bundle-secret transition, and the public packet publisher.

## Active successor dispatch

The registered local transition first reads the exact bound downstream
repository's public Actions-secret key and dispatches
`issue-write-enforcement-attestation.yml` at that immutable tag in
`seal_downstream` mode with exact key ID, decoded-key SHA-256, predecessor run
ID, and predecessor WEA SHA-256. After protected approval, the issuer validates
all five frozen Contents reads and emits only a bound sealed-box ciphertext
artifact. The checked local transition re-verifies the artifact and live public
key, submits only ciphertext plus key ID to the bound target, and proves the target secret's
name/update metadata. It then dispatches `capability_change` with the exact
sealed run and ciphertext identities. The unprotected jobs authenticate both
predecessor and sealed artifact before the second protected approval. After
approval, the issuer checks out the registered manifest population, verifies every
committed byte, issues epoch+1, completes its hosted self-check, and publishes
the closed 11-file public artifact.

This release has no recurring owner action. The Coach drives the registered
machine route, including independent review, tag creation, dispatch, and exact
pending-environment approvals. Approval uses the established non-personal OAuth
route; repository reads mint short-lived tokens from existing App installation
`159880331` and the credentials already held in
`/home/azureuser/.config/govml/env`. No new personal token, Rex approval click,
or credential relay is part of an issuance.

Inside the approved issuer environment, the registered credential selector uses
the complete App pair to mint an installation token for exact Git reads across
all five frozen repositories, then seals the token directly to REA's current
public key. The deprecated `REA_BUNDLE_READ_TOKEN` compatibility fallback is
not the release route. `REA_SECRETS_WRITE_PAT` is not used and remains narrowly
scoped to its separate rexcoleman.dev renewal-key purpose. No secret value or
plaintext digest is printed, persisted, placed on argv, or exposed to the
local transition.
The verified 11-file packet is then appended to the issuer's dedicated public
Git ref with exact run/tag/SHA/file-digest and predecessor-chain bindings, so
downstream CI needs Contents read only and no cross-repository Actions scope.
For cycle10, `provision_registered_downstream_bundle_secret.py` is the
closeable local transition. It refuses a pre-existing secret, is bound to the
exact cycle10 repository, and rolls back a newly created secret on any failed
postcheck or downstream issuance. The registered machine session executes and
approves this rail under the active authority. An external-judge route exercised
by a release gate reuses the established 2026-09-07 judge keypair; it does not
generate or rotate a key inside the release. No owner credential handling
substitutes for manifest construction, tag proof, dispatch, artifact
verification, or exact deployment approval.

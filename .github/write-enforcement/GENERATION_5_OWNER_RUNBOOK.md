# Generation-5 WEA owner runbook

Generation 5 is a successor authority over the exact 247-member frozen
manifest. It adds `ci-enforcement-materializer`, the protected downstream
bundle-secret transition, and the public attestation packet publisher.
It never edits or reuses the generation-4 manifest.

## Frozen identity

The manifest-only commit must change exactly
`.github/write-enforcement/frozen_bundle_manifest.generation-5.json`. Its
annotated protected tag is derived as `rea-wea-generation-5-` plus the first
12 lowercase hexadecimal characters of that commit. The tag must peel exactly
once to that commit and the manifest must report generation 5, 247 members,
the registered successor materializer subject, the registered protected
downstream bundle-secret transition, and the public packet publisher.

## Active successor dispatch

The checked owner arc first reads REA's public Actions-secret key and dispatches
`issue-write-enforcement-attestation.yml` at that immutable tag in
`seal_downstream` mode with exact key ID, decoded-key SHA-256, predecessor run
ID, and predecessor WEA SHA-256. After protected approval, the issuer validates
all five frozen Contents reads and emits only a bound sealed-box ciphertext
artifact. The checked local transition re-verifies the artifact and live public
key, submits only ciphertext plus key ID to REA, and proves the target secret's
name/update metadata. It then dispatches `capability_change` with the exact
sealed run and ciphertext identities. The unprotected jobs authenticate both
predecessor and sealed artifact before the second protected approval. After
approval, the issuer checks out the 247-member manifest, verifies every
committed byte, issues epoch+1, completes its hosted self-check, and publishes
the closed 11-file public artifact.

The owner arc handles no credential bytes. It approves only the exact
independent-review and issuer deployments. Inside the approved issuer
environment, the registered transition exercises the existing
`REA_BUNDLE_READ_TOKEN` with exact Git reads across all five frozen
repositories and seals it directly to REA's current public key. The
`REA_SECRETS_WRITE_PAT` is not used and remains narrowly scoped to its separate
rexcoleman.dev renewal-key purpose. No secret value or plaintext digest is
printed, persisted, placed on argv, or exposed to the owner/local transition.
The verified 11-file packet is then appended to the issuer's dedicated public
Git ref with exact run/tag/SHA/file-digest and predecessor-chain bindings, so
downstream CI needs Contents read only and no cross-repository Actions scope.
No owner action substitutes for manifest construction, tag proof, dispatch,
or artifact verification.

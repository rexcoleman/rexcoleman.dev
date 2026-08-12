# Generation-5 WEA owner runbook

Generation 5 is a successor authority over the exact 246-member frozen
manifest. It adds `ci-enforcement-materializer` and the protected downstream
bundle-secret transition, and never edits or reuses the generation-4 manifest.

## Frozen identity

The manifest-only commit must change exactly
`.github/write-enforcement/frozen_bundle_manifest.generation-5.json`. Its
annotated protected tag is derived as `rea-wea-generation-5-` plus the first
12 lowercase hexadecimal characters of that commit. The tag must peel exactly
once to that commit and the manifest must report generation 5, 246 members,
the registered successor materializer subject, and the registered protected
downstream bundle-secret transition.

## Active successor dispatch

Dispatch `issue-write-enforcement-attestation.yml` at that exact immutable tag
in `capability_change` mode with predecessor run ID and SHA-256 derived from the
currently installed authenticated generation-4 authority. The unprotected
predecessor job must pass before the protected `rea-write-enforcement-issuer`
environment asks for owner approval. After approval, the issuer must check out
the 246-member manifest, verify every committed byte, issue epoch+1, complete
its hosted self-check, and publish the closed 11-file public artifact.

The owner arc handles no credential bytes. It approves only the exact
independent-review and issuer deployments. Inside the approved issuer
environment, the registered transition first exercises the existing
`REA_BUNDLE_READ_TOKEN` with exact Git reads across all five frozen
repositories and an Actions/artifact read in rexcoleman.dev. Only after those
checks pass does it use the existing `REA_SECRETS_WRITE_PAT` to set the same
bundle-read token in the downstream REA repository over stdin, followed by an
exact name/update postcheck. No secret value is printed or placed on argv.
No owner action substitutes for manifest construction, tag proof, dispatch,
or artifact verification.

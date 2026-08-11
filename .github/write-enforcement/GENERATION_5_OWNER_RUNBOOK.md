# Generation-5 WEA owner runbook

Generation 5 is a successor authority over the exact 245-member frozen
manifest. It adds `ci-enforcement-materializer` and never edits or reuses the
generation-4 manifest.

## Frozen identity

The manifest-only commit must change exactly
`.github/write-enforcement/frozen_bundle_manifest.generation-5.json`. Its
annotated protected tag is derived as `rea-wea-generation-5-` plus the first
12 lowercase hexadecimal characters of that commit. The tag must peel exactly
once to that commit and the manifest must report generation 5, 245 members,
and the registered successor materializer subject.

## Active successor dispatch

Dispatch `issue-write-enforcement-attestation.yml` at that exact immutable tag
in `capability_change` mode with predecessor run ID and SHA-256 derived from the
currently installed authenticated generation-4 authority. The unprotected
predecessor job must pass before the protected `rea-write-enforcement-issuer`
environment asks for owner approval. After approval, the issuer must check out
the 245-member manifest, verify every committed byte, issue epoch+1, complete
its hosted self-check, and publish the closed 11-file public artifact.

The owner credential package and environment approval are one live owner arc:
the checked package provisions only `REA_BUNDLE_READ_TOKEN`, prints no secret
bytes, and reports the exact pending deployment. No owner action substitutes
for manifest construction, tag proof, dispatch, or artifact verification.

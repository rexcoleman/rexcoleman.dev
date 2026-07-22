# WEA issuer freeze sequence

The bundle does not solve a self-referential commit fixed point.

1. Commit and push issuer workflow/code, verifier, mounts, consumers, runners,
   scaffolders, public key, policy, registry, and remote-rule normalization.
2. Build `frozen_bundle_manifest.json` in a later manifest-only commit. Every
   member names its exact earlier commit, path, byte length, and SHA-256.
3. Dispatch that manifest commit. The workflow proves its current bytes equal
   the earlier frozen `remote-issuer-workflow` member and records both the
   exact execution `GITHUB_SHA` and workflow blob SHA-256 in the receipt. Thus
   the manifest can be added after the implementation freeze without a Git
   hash fixed point and without accepting mutable workflow bytes.

Any workflow/member byte change requires a new generation and a new manifest
frozen before measurement. A mutable branch name is not issuance provenance.

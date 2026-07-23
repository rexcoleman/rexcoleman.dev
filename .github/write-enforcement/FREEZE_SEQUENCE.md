# WEA issuer freeze sequence

The bundle does not solve a self-referential commit fixed point.

Generation 1 remains immutable at
`frozen_bundle_manifest.json` and protected tag
`rea-wea-generation-1-baad04428287`. Never edit, recreate, or move either.

Generation 2 uses exactly this two-commit rex sequence:

1. Commit and push every implementation/member change first. The rex
   implementation commit includes issuer workflow/code, verifier, member
   contract, this sequence, and the generation-2 owner runbook. Then update and
   push the Moonshots reusable workflow to pin that exact rex implementation
   commit, and update and push the newsletter caller to pin that exact
   Moonshots commit. All other repositories remain at their reviewed member
   commits unless an audited member actually changes.
2. Prove every selected member commit is remotely fetchable. Build
   `frozen_bundle_manifest.generation-2.json` from those exact final repository
   heads. Commit only that new file in a later rex manifest-only commit.
3. Let the 40-lowercase-hex manifest commit be `ISSUER_SHA`. Derive, never
   invent, the tag as:

   `rea-wea-generation-2-` + the first 12 hexadecimal characters of
   `ISSUER_SHA`.

   Equivalently, in a POSIX shell:

   `ISSUER_TAG="rea-wea-generation-2-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"`

4. The owner creates that annotated tag only after independently verifying the
   manifest commit and protected tag-ruleset coverage, then dispatches the
   registered issuer workflow at that tag. The workflow proves its current
   bytes equal the earlier frozen `remote-issuer-workflow` member and records
   both exact execution `GITHUB_SHA` and workflow blob SHA-256 in the receipt.
   Thus the manifest is later than the implementation without a Git hash fixed
   point and without accepting mutable workflow bytes.

Any workflow/member byte change requires a new generation and a new manifest
frozen before measurement. A mutable branch name is not issuance provenance.

# WEA issuer freeze sequence

The bundle does not solve a self-referential commit fixed point.

Historical generations are immutable:

- generation 1: `frozen_bundle_manifest.json` and protected tag
  `rea-wea-generation-1-baad04428287`;
- generation 2: `frozen_bundle_manifest.generation-2.json`, implementation
  commit `4aa684a55a6f2419b9e73aae160fc8463aa36c13`, manifest commit
  `7017e2cacdf8cdd4046f9530da669d1fa273fb6d`, and protected tag
  `rea-wea-generation-2-7017e2cacdf8`.
- generation 3: `frozen_bundle_manifest.generation-3.json` and protected tag
  `rea-wea-generation-3-<recorded-manifest-prefix>`.

Never edit, recreate, delete, or move those manifests, commits, or tags.

Generation 4 uses exactly this two-commit rex sequence:

1. Commit and push every implementation/member change first. The rex
   implementation commit includes the issuer checksum-cwd correction, hosted
   self-verification step, generation-4 contract/tests, this sequence, and the
   generation-4 owner runbook. Then update and push the Moonshots reusable
   workflow to pin that exact rex implementation commit, and update and push
   the newsletter caller to pin that exact Moonshots commit. Other repositories
   remain at their reviewed member commits unless an audited member changes.
2. Prove every selected member commit is remotely fetchable. Build
   `frozen_bundle_manifest.generation-4.json` from those exact final repository
   heads. Commit only that new file in a later rex manifest-only commit.
3. Let the 40-lowercase-hex manifest commit be `ISSUER_SHA`. Derive, never
   invent, the tag as:

   `rea-wea-generation-4-` + the first 12 hexadecimal characters of
   `ISSUER_SHA`.

   Equivalently, in a POSIX shell:

   `ISSUER_TAG="rea-wea-generation-4-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"`

4. The owner creates that annotated tag only after independently verifying the
   manifest commit and protected tag-ruleset coverage, then dispatches the
   registered issuer workflow at that tag. The workflow proves its current
   bytes equal the earlier frozen `remote-issuer-workflow` member and records
   both exact execution `GITHUB_SHA` and workflow blob SHA-256 in the receipt.
   Thus the manifest is later than the implementation without a Git hash fixed
   point and without accepting mutable workflow bytes.

Generation 4 active issuance requires the preserved expired generation-3 WEA
SHA-256 as `predecessor_wea_sha256`; omission or a non-64-lower-hex value must
refuse before signing. Any later workflow/member byte change requires explicit
new authority and a new manifest frozen before measurement. A mutable branch
name is never issuance provenance.

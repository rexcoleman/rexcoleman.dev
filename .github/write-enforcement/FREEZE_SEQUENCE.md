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

Every active issuance requires `predecessor_run_id`, the protected workflow run
whose public artifact contains the exact WEA currently installed. The issuer
downloads and authenticates those bytes, derives their digest itself, and sets
`authority_epoch = predecessor.authority_epoch + 1`. `authority_generation`
continues to identify this member-contract generation and is deliberately not
the issuance epoch. Caller-supplied predecessor digests and static generation
fixtures are refused. Any later workflow/member byte change requires explicit
new authority and a new manifest frozen before measurement. A mutable branch
name is never issuance provenance.

## Generation 5 successor

Generation 4 is now historical and immutable. Generation 5 adds the signed CI
enforcement materializer and uses the same two-commit construction without
rewriting the generation-4 manifest:

1. Commit and push all generation-5 implementation bytes, including the issuer
   workflow pin to `frozen_bundle_manifest.generation-5.json`.
2. From exact clean, remotely reachable heads of all five repositories, invoke
   `build_frozen_manifest.py` with `--successor-ci-materialization` and output
   `.github/write-enforcement/frozen_bundle_manifest.generation-5.json`. The
   builder must emit generation 5 with exactly 247 members.
3. Commit only that new manifest in a later rexcoleman.dev commit. Derive the
   annotated tag as `rea-wea-generation-5-` plus the first 12 lowercase hex
   characters of the manifest-only commit.
4. After independent exact-head review, create the protected annotated tag and
   dispatch the issuer at that tag with the authenticated installed generation-4
   predecessor run and WEA digest. Required environment approval remains the
   owner gate; all other construction and verification is executor-owned.

Before step 2 for any new successor, run the registered signed-release
convergence accelerator in `--plan` mode over the five exact clean roots. It
must complete its hermetic test matrix and two byte-identical manifest builds
before a manifest-only PR exists. Use `--noop-rehearsal` to prove the current
manifest can be rebuilt from its exact frozen commits without any remote
mutation. The accelerator never replaces independent review, protected
approval, issuance, installation, or post-install CI.

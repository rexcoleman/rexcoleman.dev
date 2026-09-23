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

Generation 4 used the historical manifest-only form of this two-commit rex
sequence:

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
enforcement materializer and keeps the same source-then-freeze identity without
rewriting the generation-4 manifest. Its current protected-PR boundary is the
normal-hook two-file contract, not the historical manifest-only form:

1. Commit and push all generation-5 implementation bytes, including the issuer
   workflow pin to `frozen_bundle_manifest.generation-5.json`.
2. From exact clean, remotely reachable heads of all five repositories, run the
   indexed signed-release convergence adapter for the intended authority
   population. Its registered `expected_member_count` is the single count
   contract. The deterministic builder must emit generation 5 with that exact
   population and output
   `.github/write-enforcement/frozen_bundle_manifest.generation-5.json`.
3. Stage the new manifest and commit through the normal pre-commit hook. The
   hook-generated `.governance/pre_commit_boundary.json` binds the base parent
   and names the manifest as the sole semantic path. The pull request must
   contain exactly those two ordered files. The independent reviewer fetches
   both at the exact head and rederives the receipt blob, parent, path/count
   digest, whole-file-set digest, and manifest SHA-256. A one-file
   manifest-only PR or a hand-written receipt refuses.
4. Let `F` be that reviewed two-file feature commit. Merge it through the
   protected normal route and require the fetched default commit `M` to have a
   tree identical to `F`. Derive the annotated tag as
   `rea-wea-generation-5-` plus the first 12 lowercase hexadecimal characters
   of `F`, and create the protected tag at `F`, not at `M`.
5. Dispatch the issuer at that tag with the authenticated installed predecessor
   run and WEA digest. The Coach uses the registered non-personal OAuth route for
   exact pending-environment approvals and the existing App installation
   `159880331` plus `/home/azureuser/.config/govml/env` for short-lived
   five-repository read authority. This is a machine route: no recurring Rex
   approval or newly minted personal token is part of a release. Any
   external-judge gate reuses the established 2026-09-07 judge keypair.

Before step 2 for any new successor, run the registered signed-release
convergence accelerator in `--plan` mode over the five exact clean roots. Use
the machine index to select the adapter; do not copy a member count from this
operator document. It
must complete its hermetic test matrix and two byte-identical manifest builds
before the two-file manifest-and-receipt PR exists. Use `--noop-rehearsal` to
prove the current
manifest can be rebuilt from its exact frozen commits without any remote
mutation. The accelerator never replaces independent review, protected machine
approval, issuance, installation, or post-install CI.

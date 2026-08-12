# Credential custody rule

Every credential this repository's enforcement chain consumes is written down
in `credential_custody.json` and enforced by `credential_custody.py check`.
This file is the human half: the owner acts that the record points at, and the
reasoning behind the rule.

## Why the rule exists

The signing key lapsed silently and cost the cycle an outage. Nothing had
recorded who held it, where it lived, when it would stop working, or what
would restore it. This rule removes each of those four blanks, and the checker
removes the possibility of the record drifting away from the workflows.

## The invariant it serves

P-6, precondition reachability: every precondition a gate requires must be
establishable by a registered transition, executable without passing through
the gate that requires it. P-6's subset proof states that satisfying a
precondition by a manual out-of-band act does NOT pass.

So a credential with no registered re-establishing transition is itself a P-6
violation. The record says so in the row, in the field
`reestablishing_transition.status = NONE_P6_VIOLATION`, and strict `check`
fails on it. That failure is the open cycle-back, made mechanical. It is not
hidden and it is not waived by default.

## Expiry, and what to do when GitHub will not tell you

`gh secret list` and `GET /repos/{owner}/{repo}/environments/{env}/secrets`
return `created_at` and `updated_at` only. There is no expiry field for a
secret's contents, and the contents are write-only. For a token minted with an
expiry, that date is therefore genuinely unreadable from inside the system.

Never fabricate a date and never leave the field blank. Record
`expiry.kind = "UNRECORDED_AND_UNREADABLE"` with the reason, and compensate
STRUCTURALLY: fill `lapse_detection` with a detector, a cadence, and a
statement of how lapse is observed before it causes an outage. The checker
rejects the marker without the compensation.

The compensation that applies to the read tokens today: the renewal scheduler
runs on `cron 17 */6 * * *`, four times inside every 24-hour authority
lifetime, and exercises both tokens on every attempt. A lapsed token fails a
renewal run at least six hours before the live attestation expires. Lapse
surfaces while enforcement is still valid. That is the difference between this
and what happened before.

## Owner acts

There are exactly two, per the binding ruling of 2026-08-07. Neither ever
involves a signing key value.

### 1. Mint the secrets-write PAT (once)

GitHub, Settings, Developer settings, Personal access tokens, Fine-grained
tokens, Generate new token.

- Resource owner: `rexcoleman`
- Repository access: **Only select repositories**, and select
  `rexcoleman/rexcoleman.dev` and nothing else
- Repository permissions: **Secrets: Read and write**. Nothing else needs to be
  raised.
- Expiration: choose a date, then **write that date into
  `credential_custody.json`** on the `REA_SECRETS_WRITE_PAT@rea-write-enforcement-issuer`
  row as `expiry.kind = "RECORDED"` with `expiry.value` set. This is the one
  expiry in the chain that is knowable, so leaving it unrecorded would be a
  choice, not a limitation.

Store it as an environment secret named `REA_SECRETS_WRITE_PAT` in environment
`rea-write-enforcement-issuer`. That environment already carries
`required_reviewers: [rexcoleman]`, so the PAT sits behind the same approval as
the signing key, and no new environment is created. Creating a new environment
is what forces fresh hand-provisioning; this rule avoids it deliberately.

### 2. Approve one issuance

Run the registered transition:

```
gh workflow run provision-renewal-signing-key.yml \
  --repo rexcoleman/rexcoleman.dev --ref main -f mode=copy
```

The `copy-signing-key` job declares `environment: rea-write-enforcement-issuer`
and waits for your approval. Approve it once. The job reads the key from that
environment and writes it into `rea-write-enforcement-renewal` through the
GitHub secrets API's public-key encryption path, then verifies the target
secret by name and refuses unless the observed `updated_at` proves that run
performed the write.

Run `mode=dry-run` first if you want the PAT scope proven with nothing written.
It performs the same permission probe and stops before the write.

You never see, generate, paste, or hold the key value at any point. If any
walkthrough ever asks you to, that walkthrough is wrong.

### Protected downstream bundle-token handoff

Generation-5 capability-change issuance also uses the already-provisioned
`REA_SECRETS_WRITE_PAT`; it does not ask the owner to mint or paste another
bundle token. After the exact issuer deployment is approved,
`provision_downstream_bundle_secret.py` reads both existing environment secrets
inside `rea-write-enforcement-issuer`. It first proves the bundle token can
read an exact signed Git commit in each of the five frozen repositories and
can download the exact predecessor artifact from rexcoleman.dev Actions. Only
then does it pass the bundle token on stdin to the downstream REA secret write,
and it refuses unless the target name and this run's update are observed. The
owner sees and handles neither credential value.

## Running the checker

```
python3 .github/write-enforcement/credential_custody.py check
python3 .github/write-enforcement/credential_custody.py check --allow-declared-open
```

Strict `check` is currently RED on this tree, by design: two rows declare
`NONE_P6_VIOLATION` because the issuer-held signing key and the second
principal's GitHub App private key have no registered re-establishing path.
`--allow-declared-open` downgrades a fully documented open row to a loud
`P6_OPEN` line, and still fails on a missing row, an incomplete declaration, a
dangling transition path, or more open rows than `--max-declared-open`. The
budget stops the waiver from quietly becoming the default.

# Signed-release convergence index

`signed_release_convergence_index.json` is the canonical discovery surface for
the reusable signed-release convergence engine and its adapters. Start here
instead of reconstructing paths from an earlier release handoff.

The index is intentionally small and closed. It names the current engine,
operator documentation, focused tests, read-only workflow, this guide, and
every registered adapter. It also points to
`signed_release_convergence_inventory.json`, the broader cross-generation,
two-repository machinery inventory. The narrow adapter registry answers
"which current planner can I run?"; the broader inventory answers "which
reusable convergence mechanisms and prior proof suites already exist?"
Each adapter row has exactly three fields:

- `adapter_id`: the stable identifier validated from the adapter itself;
- `path`: a repository-relative JSON path below the index directory; and
- `status`: `active` or `retired`.

The engine resolves an active row when invoked with `--adapter-id`. A direct
`--adapter` path remains supported for compatibility, but indexed selection is
the normal route. `--list-adapters` validates the complete index and every
adapter before printing the registered rows. Unknown, duplicate, retired,
traversing, missing, mismatched, or extra-field rows refuse.

Worked adapter discovery from this directory:

```
python3 signed_release_convergence.py --list-adapters
```

Worked adapter planning invocation from this directory:

```
python3 signed_release_convergence.py --adapter-id research-enforcement-activation-generation-5-population-290-v1 --plan --state /tmp/rea-src-state.json --evidence-dir /tmp/rea-src-plan --root research_enforcement_activation=/path/to/research_enforcement_activation --root govML=/path/to/govML --root Moonshots_Career_Thesis_v2=/path/to/Moonshots_Career_Thesis_v2 --root newsletter=/path/to/newsletter --root rexcoleman.dev=/path/to/rexcoleman.dev
```

The active registry contains the original REA authority adapter, its s155
registration successor, the Band C M1/row-26 257-member successor, the W2
project-bundle basis-resolution successor, its derived-authority-generator
successor, the two s157 dependent-project adapters for NGA and RER, their
population-257, population-259 and population-260 successors, the two s189
population-264 dependent adapters for AML and ABLL, and the two s195
population-264 dependent adapters for NGA and RER that complete the
generation-5 dependent set. The s165 population-259 AML dependent
adapter is registered but `retired`. The population-259 identities
bind the PR 759 Moonshots build roles plus both govML role checklists. A
population-preserving s169 hardening successor is registered as
`research-enforcement-activation-generation-5-s169-hardening-v1`. It binds
nested ruleset projection, expired-row scheduler semantics, consumer
object-store refresh/watch path, registration
preauthorization producer, and exact Moonshots agent-spec digests while
retaining the 259-member population. A second s169 successor is registered as
`research-enforcement-activation-generation-5-s169-hosted-principal-v1`.
It retains every hardening suite and adds the protected hosted external-judge
workflow, canonical govML hosted approval and machine client, fixed public-key
HYBRID boundary, exact-request/TTL/single-spend polarities, and the one-time
checked owner setup with tested rollback. The adapter raises the population to
260: `external-judge-authority-issuer` and verifier are existing members, while
the new hosted workflow is a genuine `remote_workflow` member because it has
custody of the approving private key. The client and setup rail cannot sign or
make an invalid authority verify, so they remain registered and tested
orchestration surfaces outside the signed member population.
A population-preserving s170 successor is registered as
`research-enforcement-activation-generation-5-s170-hosted-principal-ownership-v1`.
It retains the same hosted workflow, member population, issuer bindings, and
one-time owner boundary, while binding the public-key predecessor to the live
host identity: regular `root:root` mode `0644`. The earlier `65534:65534`
observation was a sandbox namespace artifact and is not an admissible
production precondition. The successor changes no schema and fires no setup,
issuance, freeze, WEA reissue, or F2/F3 activation.
A population-preserving s173 successor is registered as
`research-enforcement-activation-generation-5-s173-authenticated-head-rebase-v1`.
It retains the s170 hosted-principal contract and adds the consumer-side,
no-issuance authenticated-head re-base at both the machine-state renewal and
project-local installed-copy refresh surfaces. The selected adapter hermetically
tests an exact signed public-tag walk from a stale installed anchor to the
current live head, refuses a forged head and every missing or skipped
intermediate link, reuses the atomic state/libexec rollback and resume
boundary, records the ordered run/tag/commit evidence, binds the cron's
bytecode-residue prevention, and proves a consumer runner never imports the
REA working tree. The project refresh installs the byte-identical verifier as
`scripts/authenticated_head_rebase.py` in the consumer's signed managed set and
loads only that project-local path, including when the current packet still
pins a predecessor REA commit that predates s173. Registration plans and tests
these bytes; it
does not fire convergence, issue or reissue an attestation, change the WEA
generation, or activate F2/F3.
The measured installed-population successor is registered separately as
`research-enforcement-activation-generation-5-population-261-v1`. It derives
from s173 without changing that 260-member adapter, adds the installed govML
`authenticated_head_rebase.py` subject as member 261, and selects a distinct
builder contract that requires exact hosted-principal-plus-rebase membership.
It also carries the current govML C1-C3 source/test surface so a later source
plan validates the population it would actually freeze. This registration
does not build, freeze, issue, install, or activate generation 5.
The control-closure successor is registered separately as
`research-enforcement-activation-generation-5-population-264-v1`. It derives
from the 261 adapter without changing it and adds the three govML
`AUTHENTICATED_CONTROL_SOURCES` rows the consumer bootstrap requires as signed
members (`scripts/request_hosted_external_judge_authority.py`,
`scripts/external_judge_authority_lifecycle_self_test.py`,
`scripts/gen_infrastructure_index.py`) as members 262-264, selected by the
distinct `--control-closure-successor` builder contract. The 261 manifest
refused `CONTROL_CLOSURE_MEMBER_ABSENT` under its own consumer because those
rows were absent. This registration does not build, freeze, issue, install, or
activate generation 5.

Three population-264 dependent adapters register the publication surfaces named
by the cycle's 2026-07-11 amendment - the report, blog, publication and
distribution boundary where claims actually reach readers:
`newsletter-hybrid-path-generation-5-population-264-v1`,
`newsletter-generation-5-population-264-v1` and
`rexcoleman.dev-generation-5-population-264-v1`. They derive from the s189/s195
dependent-adapter contract without changing it: the five-root signed-authority
plan, the 264-member control-closure population, the hermetic suites and the
boundaries are identical, and the three per-project fields - `adapter_id`,
`dependent_project.project_id` and `dependent_project.repository` - are the only
divergence. Registration plans these identities; it does not build, freeze,
issue, install, enrol or arm any of the three repositories, and in particular it
does not arm a commit boundary on `newsletter` or `rexcoleman.dev`, which carry
live publication traffic.

The governed-read-credential successor is registered as
`research-enforcement-activation-generation-5-s210-governed-read-credential-v1`.
It derives from the 264 adapter without changing it. Every issuance and renewal
run begins by checking out the four frozen repositories, and until now that
checkout could only authenticate with an expiring personal access token; when
that token lapsed the whole portfolio froze on `WEA_EXPIRED` with no registered
path back. The adapter adds the two rexcoleman.dev modules that replace it as
members 265 and 266 - `.github/write-enforcement/github_app_installation_token.py`,
byte-identical to the signed govML template copy, and
`.github/write-enforcement/select_governed_read_credential.py`, which
implements the custody precedence - and selects the distinct
`--governed-read-credential-successor` builder contract, so the 260-, 261- and
264-member contracts continue to refuse these two subjects. They live in the
rexcoleman.dev population rather than in govML because they run on the hosted
runner BEFORE the authenticated checkout succeeds, when rexcoleman.dev is the
only source on disk; the issuer workflow closes the resulting three-copy drift
loop by asserting the minter against `repos/govML` on every run. This
registration does not build, freeze, issue, install, or activate generation 5,
and it does not create the GitHub App, which is an owner act behind the owner's
GitHub session.

The s212 recovery successor is registered in the cross-generation inventory as
three inseparable surfaces: the no-argument transaction engine, the hosted
non-disclosing credential probe, and their focused planted-polarity tests. It
converges the legacy issuer/renewal pair, the exact five-repository GitHub App
pair at issuer/renewal/approver, and the hosted approving principal plus its
root-owned public half. It ends at credential readiness: F3, issuance, freeze,
tagging, and every Mac surface remain outside this rail. The source and
operating contract are documented in `WEA_CREDENTIAL_RECOVERY.md`.

The s226 population-273 successor is registered as
`research-enforcement-activation-generation-5-population-273-v1`. It derives
from the population-265 pre-commit-boundary successor and adds the eight
govML construction-completeness fixture evidence subjects that became managed
install members when PR #186 made the honest construction fixture discriminate
by exit code. The old population-265 adapter remains auditable, but the active
reissue plan uses the 273-member contract so the frozen manifest cannot omit
bytes that `managed_enforcement_inventory.py` installs.

A population change always gets a new stable
adapter identity; the 251- and 255-member adapters remain
auditable without being silently redefined. The dependent adapters use schema
v2: in addition to the unchanged
five-root signed-authority plan they close over the exact dependent repository,
default branch, project-owned runner and preflight argument, required
`SIGNED_BUNDLE` source, and named refusal. The engine records that identity in
the contract receipt but keeps release/install mutation outside the planner.

## Adding or changing an adapter

1. Add or update the adapter JSON under `adapters/`.
2. Add exactly one matching row to the machine index. Never reuse an existing
   identifier for different semantics.
3. Extend the focused tests for the adapter contract and planted refusals. A
   dependent adapter must cover hermetic execution, exact target identity,
   resume, refusal, source-root poststate, and durable contract evidence.
   A population successor uses the closed
   `<project>-generation-<generation>-population-<count>-v1` identity; the
   loader refuses when the suffix count and `expected_member_count` diverge.
4. Update `SIGNED_RELEASE_CONVERGENCE.md` when the operating boundary changes.
5. Run the internal self-test and focused test file. The read-only
   `signed-release-convergence` workflow repeats both on the pull request.

The index is navigation and contract metadata, not release authority. It does
not merge, tag, approve, issue, install, or prove a target project green.

## Cross-generation inventory and reconciliation

The inventory has 36 closed rows spanning s88, s127, s131, s132, s149, s153,
s154, s155, s157, s165, s169, s170, s173, s180, and s188 in govML and
s212 in rexcoleman.dev. Each row names a stable identity, remote
repository/default branch, path, session generation, kind, semantic discovery
markers, and the tested properties it supplies. The six required properties
are hermetic execution, identity binding, resume, refusal, poststate, and
evidence. `untested_properties` is derived from their status map; it is empty
only while each property remains backed by a registered test.

`enumerate_signed_release_convergence.py` reconciles the inventory by two
independent Git methods against fetched `origin/main`: tree identity via
`git ls-tree`, and semantic discovery via fixed-string `git grep` markers.
It emits both counts, their percentage delta, and one row per result; any
missing row or delta above five percent is nonzero. This is the required
preflight before adding a new convergence implementation. Reuse a registered
engine/adapter/test/evidence row, and add a row only when no existing mechanism
covers the requirement.

Worked inventory enumeration from this directory:

```
python3 enumerate_signed_release_convergence.py --inventory signed_release_convergence_inventory.json --repo govML=/path/to/clean/govML --repo rexcoleman.dev=/path/to/clean/rexcoleman.dev --json-out /tmp/signed-release-convergence-enumeration.json
```

The s165 row registers `rehearse_generation5_ruleset_revert.py`. It reuses the
generation-5 manifest builder, derives all five immutable member commits from
the frozen manifest, clones only from the five gios-dev object stores, and
double-builds from a supplied post-revert ruleset file. Its normal invocation
requires only `--ruleset-json`; the output location has a deterministic default.
It refuses a non-empty bypass, member drift, a third changed manifest field, or
non-deterministic output, and performs no remote or installed-state mutation.

The second s165 row registers the population-259
`adversarial_ml_landscape` dependent adapter. It binds the Moonshots
`--converge-enforcement` genesis transition from a committed
`PENDING_SIGNED_BUNDLE` sentinel to the authenticated bundle's exact govML
commit, requires refusal rollback to the original governance bytes, and retains
the dependent project's own post-issuance runner as the acceptance surface.
That row's index status is now `retired` and its successor is
`adversarial-ml-landscape-generation-5-population-264-v1`. The adapter named
`rexcoleman/adversarial_ml_landscape` as the dependent repository; that
repository does not resolve, and the real remote is
`rexcoleman/adversarial-ml-landscape`. `retired` is the only withdrawal status
the closed index row schema admits, so it carries the supersession. The
identifier is retained, not deleted, and a retired row refuses selection.

Two s189 population-264 dependent rows register
`adversarial-ml-landscape-generation-5-population-264-v1` and
`agent-boundary-learning-landscape-generation-5-population-264-v1`. Both derive
their signed-authority plan from the 264 control-closure successor without
changing it, and each closes over its own real remote, `main` default branch,
`scripts/run_gates.sh` runner, `--engine-preflight` argument, required
`SIGNED_BUNDLE` source, and the `GOVERNANCE_ENGINE_REF_MISMATCH` refusal. The
loader derives the dependent repository from `project_id`, so the AML successor
uses the hyphenated `adversarial-ml-landscape` project identity in order to
name the repository that exists; `agent_boundary_learning_landscape` keeps its
underscored identity because that is its real remote. Both reuse the registered
engine, adapter schema v2, and focused test file, so neither adds a
cross-generation inventory row.

Two s195 population-264 dependent rows complete the generation-5 dependent set:
`newsletter-generation-architecture-generation-5-population-264-v1` and
`research-engine-release-generation-5-population-264-v1`. They exist because the
registered successor binding
(`research_enforcement_activation/scripts/s157_dependent_successor_propagation.py`)
targets exactly these two dependents and derives its expectation from the named
adapter's `expected_member_count`. While their newest adapters stopped at
population-260 and the installed bundle had moved to 264, that binding refused
`RENEWAL_POPULATION_REFUSED installed=264;expected=260` on every hourly renewal,
which is a correct refusal reporting a real gap rather than a defect in the
binding. Both new rows derive their signed-authority plan from the 264
control-closure successor without changing it — all nine authority-shared fields
are asserted equal to
`research-enforcement-activation-generation-5-population-264-v1`.

Unlike the two landscape rows, these two keep their own dependent routes rather
than the landscape literal: NGA closes over `main` with the `F09` refusal, and
RER closes over **`master`** with the `AUTHORITY_LAPSED` refusal, each carried
forward from that dependent's own population-260 predecessor. The four
parametrized population-264 dependent tests are generic over the adapter, so
both new rows inherit hermetic execution, evidence and source-root poststate,
planted route-drift refusal on all six route fields, and population-identity
drift refusal. Their population-260 predecessors are deliberately left `active`:
the closed-index test pins those two identifiers as active, and retiring them to
mirror the AML supersession would have required editing that assertion, which is
not a change an added route may make. Both reuse the registered engine, adapter
schema v2, and focused test file, so neither adds a cross-generation inventory
row.

## s229 durable history and enrollment successor

The indexed authority adapter `research-enforcement-activation-generation-5-population-290-v1`
selects `--durable-history-successor`. Its 290 members are derived from the
closed union in `durable_history_successor_members`, including the historical
pre-commit population, governed App credential members, durable signed-run
history, independent trust-root copy, runtime transaction/health machinery and
enrollment inheritance. Publisher, history, scheduler, health, interruption and
enrollment tests are explicit hermetic inputs. The prior273contract is preserved.

Matching newpopulation adapters preserve the exact routes of AML, ABL, NHP,
NGA and RER. Static propagation must select these new identities before a new
population is installed; leaving an oldcount adapter in place correctly refuses.
A new adapter does not enroll, approve or mutate any dependent. Future enrolled
repository discovery remains independently revalidated and cannot grant authority.
See [DURABLE_ATTESTATION_HISTORY.md](DURABLE_ATTESTATION_HISTORY.md) for initial
backfill ordering and what the source tests do not prove.

## s231 authenticated-packet rollout successor

Six population-next rows preserve the established REA, AML, ABL, NHP, NGA and
RER routes while selecting `--final-runtime-rollout-successor`.  Their count is
the size of `final_runtime_rollout_successor_members()` and is one greater than
the immutable population-290 contract because the only added signed subject is
`final-runtime-rollout` at
`research_enforcement_activation/scripts/s231_final_runtime_rollout.py`.

The REA operator procedure is
`research_enforcement_activation/docs/s231_final_runtime_rollout.md`.  Before
freeze, only its packet-shaped fixture contract runs.  After issuance, the exact
authenticated packet is validated into a closed execution record; the same
packet must pass unchanged and refuse a planted mixed closure before runtime
mutation.  The execution record binds commits, manifest/WEA digests, issuer
run/attempt, protected tag, epoch, all members, transitive runtime relationships,
and poststate expectations.  It is not signing, issuance, installation, or live
health evidence.

The REA row alone also opts into the closed disposable-durable fixture contract.
It revalidates the five roots from the roots-phase receipt, authenticates the
exact public packet and immediate predecessor in a fresh credential-free HOME,
then requires JUnit and the pytest outcome plugin both to report zero skipped,
xfailed, or xpassed cases. The parent must be admitted by the exact authenticated
REA production ephemeral-root predicate; descriptor-relative packet reads bind
the validated source through copy. Held descriptors and repeated identity checks
also bind every fixture-root, HOME, and packet-destination ancestor through
authentication, test execution, and cleanup, refusing same-target rename/symlink
substitution. The packet copy is explicitly fixture-only and is deleted on success or refusal;
dependent population-next adapters retain their prior behavior because the
field is optional and absent from their rows. A present null or open fixture
object refuses; only complete absence selects legacy adapter behavior.

The callable independent review route selects the unique highest active REA
generation-5 population row in this canonical index and derives the adapter's
builder selector through a structural parse of the protected member-contract
literals and full production-successor call graph. The adapter must select the
graph's unique terminal successor, and its population number must equal that
selector's derived map size. It never imports or executes the reviewed
candidate and does not depend on a successor manifest being published before
its source. A missing, duplicate, malformed or lower-only index refuses. Exact
current-map equality is required, so omissions, additions, and mixed rows also
refuse while the existing exact-head, manifest-SHA, file-set, ruleset, and
installation-scope predicates remain unchanged.

Historical retired REA population rows remain identity/path validated and are
excluded from active selection. A retired lower row cannot block a coherent
active terminal, while a retired terminal with only a lower active row refuses.

The rex identity remains the canonical two-commit freeze: signed members name
source commit R; the reviewed manifest/pre-commit-boundary feature commit F is
the protected tag and receipt target; fetched default M is F's tree-identical
merge.  The rollout validator records all three and refuses a signed-member
change in either interval, a malformed boundary receipt, or a tag not derived
from F.

The static propagation source names the five population-next dependent adapters.
Every population-290 row remains registered and unchanged for historical audit.

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

The engine's refusal evidence contract includes a durable
`hermetic-refusal.json` outside the disposable authenticated fixture. It binds
failed/error node IDs, the child exit code, complete stdout/stderr digests, and
bounded 4,096-character stream tails so a failed registered plan remains
diagnosable after fixture cleanup.

The index is navigation and contract metadata, not release authority. It does
not merge, tag, approve, issue, install, or prove a target project green.

## Cross-generation inventory and reconciliation

The inventory has 38 closed rows spanning s88, s127, s131, s132, s149, s153,
s154, s155, s157, s165, s169, s170, s173, s180, s188 and s248 in govML and
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

The primary population adapter additionally registers the runnable S131
five-root manifest-builder case. `signed_release_convergence.py` passes the five
already-authenticated roots through its closed hermetic environment, and the
test requires both terminal-successor acceptance and historical-selector
refusal. Missing root bindings cannot degrade to an accepted skip because the
adapter enforces a structurally zero-skip JUnit result.

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

For a normal-hook site-manifest PR, the callable reviewer requires the ordered
two-file set consisting of the generation-5 manifest and
`.governance/pre_commit_boundary.json`. It fetches the canonical receipt bytes
at the exact head, matches their Git blob to the PR file row, binds the receipt
parent to the PR base SHA, and rederives the sole semantic manifest path, count,
and path digest. The exact whole-file-set digest and manifest SHA remain
predeclared independent inputs.

The same callable route requires the active main ruleset's exact four-rule
population, including one strict `required_status_checks` rule with create
bypass disabled and exactly `artifact-integrity-exact-commit` plus
`pre-commit-boundary-asserted`. Missing, extra, duplicated, non-strict, or
misdirected required-check state refuses before a PASS record can be emitted.

Historical retired REA population rows remain identity/path validated and are
excluded from active selection. A retired lower row cannot block a coherent
active terminal, while a retired terminal with only a lower active row refuses.

The rex identity remains the canonical two-commit freeze: signed members name
source commit R; the reviewed manifest/pre-commit-boundary feature commit F is
the protected tag and receipt target; fetched default M is F's tree-identical
merge.  The rollout validator records all three and refuses a signed-member
change in either interval, a malformed boundary receipt, or a tag not derived
from F.

The static propagation source names the six population-next consumer adapters.
Every population-290 row remains registered and unchanged for historical audit.

The s232 population-296 successor registers five canonical govML research
templates required by the nested research-working-root materializer. All six
population-next adapters select the distinct
`--research-working-root-template-successor` terminal. Population 291 and its
adapters remain unchanged for historical audit. The exact-set contract requires
all five template paths together and binds each to the selected remotely
reachable govML commit, byte length, and digest; partial or substituted template
populations refuse. Registration alone does not freeze, tag, issue, install, or
activate the successor.

The s242 population-297 successor closes the remaining runtime dependency set.
The profile-local artifact-producer validator used by the nested working-root
initializer is already signed under its canonical member ID; the successor
adds only the existing quality-loop cleanliness gate that the installed gate
stack actually invokes.
The accompanying govML installer mapping also places the already-signed
Moonshots `signed-hypothesis-gate` member at `scripts/hypothesis_gate.sh`; this
repairs its missing child lookup without increasing the population. The same
landing repairs that canonical member's split-root authority binding and enrolls
its focused branch-C prerequisite suite in every population-297 adapter.
All six enrolled population-next adapters select
`--research-runtime-dependency-successor`; population 296 remains registered and
unchanged for audit. This source registration does not freeze, tag, issue,
install, or activate the successor.

The s249 population-300 successor repairs failure class 15 (hardening queue
row 252). It adds exactly the three canonical govML role checklists that the
Stage 0-5 agent specs require through `agent_pre_check_runner.sh --role
orchestrator|rp|verifier` - `canonical-orchestrator-checklist`,
`canonical-rp-checklist` and `canonical-verifier-checklist` - to the immutable
population-297 contract, selected by the distinct `--role-checklist-successor`
builder contract. Six population-300 adapters (REA, AML, ABL, NHP, NGA and
RER) derive from their population-297 predecessors with only `adapter_id`,
`expected_member_count` and `manifest_builder_flag` changed, so REA's static
propagation can name population-300 dependents before a 300-member bundle is
installed. Population 297 remains registered, active and unchanged for audit;
its contract still refuses the three new subjects. Dependent registration is
identity-only. This source registration does not freeze, tag, issue, install,
or activate the successor.

The s250 population-305 successor repairs failure class 20. It adds exactly
the five canonical, intentionally unfilled govML Stage 5 scaffolds required by
the signed working-root materializer to the immutable population-300 contract:
`ARTIFACT_CONTRACT.tmpl.md`, `RUNTIME_EMIT_SPEC.tmpl.md`,
`ACCEPTANCE_CRITERIA.tmpl.md`, `construction_manifest_spec.tmpl.json`, and
`construction_manifest.tmpl.json`. The distinct
`--stage5-build-template-successor` builder contract requires all five as
`100644` blobs. Six population-305 adapters derive from their population-300
predecessors with only `adapter_id`, `expected_member_count`, and
`manifest_builder_flag` changed; population 300 remains registered and active
for audit. This source registration does not freeze, tag, issue, install, or
activate the successor, and the scaffolds contain no completed cycle content.

The s252 exact-plan recovery-drive adapter is registered as
`research-enforcement-activation-generation-5-exact-plan-recovery-drive-v1`.
It does not change the 305-member population or select a new builder contract;
instead it requires the convergence engine's optional
`exact-plan-recovery-drive` phase. That phase binds the planned manifest,
adapter, engine, five roots, authenticated predecessor packet, staged
nonproduction candidate authority, umask `002`, umask `022`, the real govML
recovery installer, the REA renewal consumer, and the REA commit-preflight
surface before poststate. The s249 scratch drive is input-only context and is
not trusted code. The focused test file plants omitted-member, changed-byte,
wrong-mode, wrong-predecessor, wrong-root-commit and mixed-packet refusals.
The adapter plans evidence only; it does not release, install, repoint, merge,
or run commit preflight.

## Known failure classes (s250 catalogue)

Read this table before diagnosing a refusal on the REA release, recovery,
renewal or commit chain. Each row names the class, the refusal it surfaces as,
where it was measured, and its repair status. The cross-generation inventory
is a closed mechanism schema (adapter, engine, evidence-suite, test); a class
enters the inventory only when a registered, tested mechanism guards it, so
classes without one are catalogued here only. Changing the inventory schema
would change the engine bytes that REA pins, which is itself class 3.
The catalogue below is current through release 4 and class 22.

| # | Class | Surfaces as | Measured | Status |
|---|---|---|---|---|
| 1 | Signed mode contract 100644/100755 | member mode mismatch at install or bootstrap | s244 (`D-s244-MODE-CONTRACT`) | repaired at source; every release must carry the mode-only change |
| 2 | Predecessor-signed source misclassified as a predecessor-installed destination (queue row 246) | `COMMITTED_PREDECESSOR_MEMBER_REFUSED:scripts/hypothesis_gate.sh` in the hop-194 recovery census | s247, s248 | hardening queue row 246 BUILT: fixed in govML PR #228 (`ca8e3c42`); guarded by inventory row `s248-row246-census-introduced-destination-test`; takes effect only once a release freezes it as the control commit (class 13) |
| 3 | Transitive engine-pin drift | `CONVERGENCE_INVENTORY_REFUSED` (pinned engine `4225382`/`ac6836a4` refuses `MANIFEST_BUILDER_FLAG_REFUSED` on the population-297 adapter flag); `ROLLOUT_TRANSITIVE_PIN_REFUSED:propagation:convergence-engine` | s240, s247, s248 (reproduced rc 2 vs current engine rc 0) | repair is the s247 combined successor on REA PR #589; lands only after REA commits |
| 4 | Adapter population drift, 291 vs 297 | `SOURCE_POPULATION_REFUSED source=297;registered=291` in the dependent refresh | s247, s248 | open; REA-owned bytes, lands only after REA commits |
| 5 | Issuer unfrozen-module digest-table drift | `UNFROZEN_MODULE_PIN_PASS` step fails when a pinned module changes without its workflow digest | kc-98 | catalogue only; any edit to a pinned issuer module must update the workflow table in the same PR |
| 6 | Scheduled-issuer race | a manual capability issuance refuses public publication because a scheduled `renew` finalized a newer predecessor | s247 (run 35928505518 vs 35923088452) | handled by the registered `public_retry` mode |
| 7 | Ruleset `bypass_actors` omitted from the ruleset read | plan refuses after hermetic phase; the App token cannot read bypass actors | s247 attempt 3 | handled by the registered non-personal OAuth ruleset read |
| 8 | Renewal consumer selecting session roots | hourly log `root=/data/rea_preserved/...` or `root=.../s241-current`; worktree enumeration admits any registered REA worktree outside the ephemeral predicate | s246, s247, s248 | repair is the fixed durable root in the s247 combined successor; lands only after REA commits |
| 9 | Releasing before consumer convergence locks REA | REA's tracked managed bytes and pin lag the newest packet; every selector refuses | s240, s244 | ordering rule: a release that moves REA-owned members is issued only after REA lands them |
| 10 | Historical recovery hop expiry | the recovery installer's in-transaction `write_enforcement_state.py status` refuses `WEA_EXPIRED` for a staged historical target; each hop is possible only while its own packet is unexpired | s248 (194 expires 2026-09-24T07:17:46Z) | hardening queue row 248, open. `authenticated_head_rebase.py` bypasses intermediate expiry only on the plain stale-packet refresh, which also requires the consumer pin to equal the head's govML commit, so a pin-lagging consumer cannot use it |
| 11 | Umask-dependent preserved-ledger mode | committed ledger records `0775`; umask 022 → `DISPLACED_ENFORCEMENT_SLOT_OCCUPIED`, umask 002 → census mode refusal | s248 (scratch reproduction), s249 (real multi-hop drive) | hardening queue row 247 BUILT: govML PR #230 (`6f93cbb7`) sets each committed, byte-clean checked-out slot, ledger and predecessor destination to its authority mode when the difference is umask-attributable, journals and restores on refusal, and keeps every comparison exact; hops 194-197 then pass under umask 022 and 002. Takes effect only once a release freezes it as the control commit (class 13) |
| 12 | Refusal relabelling hides the real cause (hardening queue row 249) | `AUTHORITY_APP_AUTHENTICATION_REFUSED` wraps `APP_EXECUTABLE_AUTHENTICATION_REFUSED` (tracked tool bytes ≠ signed members), which reads as a credential fault | s248 | BUILT: govML #235 (`c50c8e7e`, row 249 r2); carried by release 3 (tag `rea-wea-generation-5-fdf66f37043d`) |
| 13 | A recovery fix reaches the consumer only by release | the successor recovery executes its installer from the CONTROL commit, which is the govML commit signed by the newest public packet; a fix merged to govML main is inert (running from it refuses `AUTHORITY_GOVML_LOCK_MISMATCH`) until a release freezes it | s248 | ordering rule (kc-99 R3): issue such a release only after a scratch drive against that exact planned release proves the consumer's recovery completes with no hand-set modes and the post-recovery hook clears |
| 14 | Recovery installs historical hops at the control's mode contract (hardening queue row 251) | `DISPLACED_ENFORCEMENT_SLOT_OCCUPIED:.governance/preserved_enforcement/scripts/artifact_class_integrity.py` at the first hop that crosses from the legacy blanket-0755 installer generation (govML `753e3ab`, packets 194-197) into the signed-mode-contract generation (`e6a968de`, packet 198). The control installer wrote the legacy targets at its own exact mode (0644), while the predecessor proof authenticates what that generation really installed (0755) | s249 (real multi-hop drive, both umasks; classifier called directly on the preserved hop-198 inputs) | open; repair: a recovery advance installs each target at `_authenticated_managed_install_mode(target_manifest)` and refuses when that mode is unauthenticated |
| 15 | Signed population lacks the role checklists the agent specs require (hardening queue row 252) | `agent_pre_check_runner.sh --role orchestrator` (also `rp`, `verifier`) FAILs Check 0 `Checklist file not found: <root>/write_integrity/bundle/govML/checklists/orchestrator.checklist` on a build-type authority root with `f_c_checklist: enabled`; population 297 signs only `research_integrity`, `build_runner` and `build_orchestrator` checklists | s249 (measured on a scratch clone recovered to epoch 200) | BUILT: rex #241 (`2ea3293e`, population-300 role-checklist successor); carried by release 3; proven by orchestrator pre_check rc 0 with the planned bundle |
| 16 | Recovery census binds destinations to a stale HEAD across uncommitted hops (hardening queue row 253) | `DISPLACED_ENFORCEMENT_SLOT_OCCUPIED:.governance/preserved_enforcement/scripts/research_type_registration_catalogs.json` on the release-2 hop after generations 194-200 were installed without an intermediate commit; the census proves each destination through the committed HEAD blob | s249 (real REA recovery) | BUILT: govML #237 (`fdd203c1`); takes effect with the next release control (release 4); measured workaround remains a hooked commit at the admissible generation |
| 17 | Signed hash-locked CI requirements carry one wheel hash (hardening queue row 254) | every REA workflow run refuses `THESE PACKAGES DO NOT MATCH THE HASHES` for `cffi==2.0.0` at dependency provisioning (runner cp313 wheel `c8d3...` vs signed `3e17...`) | s249 (REA runs 36031277703, 36031705962) | BUILT: govML #234 (`8dfdc56d`); every runner wheel hash verified by pip download and sha256; carried by release 3 |
| 18 | Pre-push source adoption compares an incomplete closure (hardening queue row 255) | `REFUSE(APP_PROBE_RUN_FAILED)` on every REA push: the workflow bytes equal the remote default, so the pre-push App probe runs on the remote's broken dependency closure (class 17), including for the push carrying the repair | s249 (REA backlog push) | BUILT: govML #234 (`8dfdc56d`); adoption compares the complete signed CI closure; carried by release 3 |
| 19 | Hook-exported Git environment overrides an explicit engine repository (hardening queue row 256) | `APP_ADOPTION_ENGINE_REPOSITORY_INVALID` on a push from a linked worktree: Git exports an absolute `GIT_DIR` to hooks, so the enrollment tool's `git -C <govML> config --get remote.origin.url` resolves REA's origin instead of govML | s249 (direct reproduction with and without `GIT_DIR`; first release-3 landing push) | BUILT: govML #238 (`4ec6d7dd`); repository-selecting Git subprocesses clear ambient `GIT_*` variables, with planted linked-worktree and hostile-environment tests; carried by release 4 |
| 20 | Signed population lacks the canonical Stage 5 scaffold sources | `init_research_working_root.py` must refuse materialization because one or more Stage 5 template subjects cannot be authenticated from the signed member population; population 300 contains none of the five canonical sources | s250 (Moonshots split-root Stage 5 materializer and govML signed-template tests) | BUILT: govML #240 (`c6580767`, merged as `13a78fa5`) and rex population-305 successor; takes effect only after REA pins converge and a kernel-owned release freezes the 305-member contract |
| 21 | Registered split-root completeness router and installed gates use incompatible CLIs | Moonshots supplies the atomic `--authority-project-dir` / `--working-project-dir` pair, but the installed REA coverage and construction gates accept only legacy `--project-dir`; after adopting the gate, the construction wrapper still refuses because it omits the canonical construction-manifest argument | s251 (Branch C live registered-route audit plus complete/one-item-omission polarities) | BUILT at source: govML #240/#241 carry the four repaired tools, govML #242 (merge `3cd881ea`) registers their derived production-authority identities, and Moonshots supplies `branch_c/outputs/construction_manifest.json`; the 60-test focused authority suite and complete/one-item-omission polarities pass. A trial unsigned REA adoption correctly refused `DISPLACED_ENFORCEMENT_SLOT_OCCUPIED`, so activation remains release-ordered: population 305 must freeze the repaired govML head, then REA recovery must bind the signed installed population before the route is represented as authenticated |
| 22 | Renewal health collapses REA-local success and older-dependent successor refusal into one verdict | I19 reports `CONVERGENCE_INVENTORY_REFUSED` as if REA renewal failed even when the wrapper retained a valid local success, hiding the transaction boundary and falsely blocking REA work | s251 (live epoch-205 wrapper log; local success plus dependent refusal; malformed-local, expired and missing-observation plants) | REPAIRED in Moonshots PR #1525 (`fd715697`): schema v2 reports `rea_renewal` and `dependent_successors` independently; process exit gates REA-local health while the older-dependent component remains explicit and nonzero. Current live result is REA `CLEAR/0`, dependent `DEGRADED/1` |

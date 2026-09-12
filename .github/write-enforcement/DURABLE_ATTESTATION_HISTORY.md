# Durable issuer history and retention recovery

The existing eleven-file public packet remains unchanged. Its annotated
`rea-wea-generation-packet-<run>` tag preserves bytes, but neither that tag nor
an unsigned receipt proves that its issuer workflow finished successfully: the
publisher runs before workflow completion. Actions artifacts, workflow runs,
checks and statuses all have finite retention. Ordinary readers therefore never
use any of those retained surfaces to choose or authenticate historical authority.

`durable_attestation_history.py` authenticates every packet against the independently
installed/pinned WEA public key. It checks WEA and predecessor signatures, exact
epoch edges, the unchanged 24-hour lifetime, signed manifest and copied member
bindings, signed hybrid authority, workflow bytes, receipt identity and checksums.
Four measured historical eleven-character generation refs are admitted only
by exact run/ref/full-commit/workflow-blob identity. New finalization requires the
current twelve-character generation format. Approximate legacy matches refuse.
Expiry of a historical link is permitted; expiry of the candidate installed by the
normal runtime verifier is still refused. The packet never selects its trust root.

The existing issuer workflow's `history_finalize` mode uses the existing
`rea-write-enforcement-renewal` environment and existing Ed25519 key. It signs
only completed prior issuer run dispositions. Each record binds repository,
workflow, attempt, event, tag/ref/head, all eleven packet hashes, epoch/predecessor,
and the preceding record's hash. Failed issuer packets receive signed failed
dispositions and never advance the successful chain. Pending, ambiguous, missing
or mismatched terminal evidence refuses. No new approving principal or key is used.

Records live at `rea-write-enforcement-history/record.json` behind annotated
`rea-wea-generation-history-<run>` tags covered by the existing protected generation
tag prefix. Public Git transport fetches the packet/history prefixes into a temporary
bare object store and executes no checkout code. Finalization queries one recent
Actions run per unfinalized packet, builds all records locally and atomically pushes
all new tags. A separately fetched poststate must contain each exact signed byte
sequence. Local unpushed refs cannot prove publication. Interrupted publication is
settled by immutable remote bytes; conflicting records are never forced or replaced.

Before the authoritative push, publication admission reads the current Actions
run and attempt, the unique active job's actual start time, and the literal job
timeout in the immutable workflow at that run's commit. History finalization
explicitly declares 360 minutes and requires 900 seconds remaining. Packet
publication in each 20-minute issuer job requires 300 seconds remaining, checked
before object creation and again immediately before creating its public tag ref.
Missing, ambiguous, future-dated or exhausted job timing refuses before the write.
Elapsed time includes earlier job steps, not just the publisher process lifetime.
The existing Actions-read permission supplies this evidence; no new grant is used.
Admission emits a nonterminal stderr record binding the actual numeric job id,
run/attempt, workflow commit and measured allowance. Final publication/resolver
stdout keeps its existing schema. Publisher GitHub children receive only the
scoped GitHub token and the shared explicit runtime environment allowlist.

These reserves are operational allowances, not finite network latency guarantees.
The atomic push has no client kill timeout. Automatic supersession is disabled,
but platform deadlines, manual cancellation and crashes still exist. A killed
observer cannot claim success; the next invocation must establish the exact remote
outcome. Atomic Git ref updates constrain partial publication, not remote durability
under every failure or guaranteed receipt of acknowledgment. Cold/warm local tests
include initial Git fetch and final resolution with synthetic signed packets and
injected Actions GET data. They do not establish hosted GitHub timing. Preserve
that boundary when using the measurements to assess the declared job budget.

Normal `resolve` and `export` require the complete packet population to have signed
dispositions. They refuse an unknown tail instead of silently selecting older
success. `successful_rebase_rows` supplies only certified successful edges to the
existing historical chain verifier. This resolver serves the publisher, scheduler,
both issuer predecessor preflights, REA consumer and governed project bootstrap.

The scheduler's `prepare` first settles an interrupted prior finalization, then
resolves the complete head. A verified prefix may select a finalizer executable
ref only: that prefix is never returned as current enforcement. The generation
ref is checked against the signed workflow head before dispatch. After a renewal
finishes, finalization must finish before scheduler success. Seal-only and
finalizer-only runs publish no WEA packet and cannot become candidates.

## Deployment order and refusal recovery

The first deployment must publish reviewed source, use the indexed successor
contract, and dispatch `history_finalize` on the new reviewed generation tag while
prior run metadata still exists. This backfills the historical dispositions before
the first new capability issuance. The release coordinator must finalize that new
completed issuance too, before unattended scheduling relies on its new generation
ref. The scheduler cannot bootstrap from an empty signed history and must not
invent a trust anchor. Historical metadata already deleted before backfill is a real
refusal; increasing retention does not restore it. A rerun whose latest run attempt
no longer matches its immutable packet also refuses rather than guessing.

The new signing mode and its source/public-key digest pins land together. Preserve
the independent public key bytes, old closed member populations, and old packet
contract versions. Derive the new member count from `durable_history_successor_members`.
The indexed adapter includes publisher, history, scheduler, consumer transition,
health, enrollment and propagation tests. Re-freeze and live adoption remain the
release coordinator's work; source registration does not assert deployment.

## Local transition and health

REA writes and fsyncs a temporary journal of both live/staged directory identities,
then publishes its canonical name with an atomic no-clobber hardlink before the
first state/libexec exchange. Partial temporary residue is never authoritative;
a kill before publication leaves the unchanged live pair available for retry. Recovery checks every path and identity before changing
either pair, then restores the previous state and libexec in reverse order. It runs
before remote discovery and can itself restart after interruption. The existing
shared install lock serializes this operation. Dry-run refuses an unsettled journal
without recovering it. No external timeout may interrupt the foundation transaction.
Isolated tests enter normal consume(), kill during partial journal writing or
before, between and after its real exchanges, then enter normal consume() again
to recover and converge. Omitting the actual journal invocation or publishing a
partial canonical journal makes these controls fail. The verifier functions are
explicit fixture seams for these wiring tests; separate packet-authentication
tests do not turn this into one fully cryptographic integration proof. Primitive
recovery interruption and malformed-journal refusal are also tested.

The cron emits one end-to-end terminal result after propagation. Local install
success is diagnostic until propagation succeeds. Health accepts only explicit
terminal outcomes, never timestamped diagnostic noise; legacy nonzero outcomes
remain failures. Same-epoch convergence does not refresh `last_authority_advance_utc`.
Missing, malformed or unauthenticated held authority is UNKNOWN/nonzero. A signed
expired authority is expired, without an unsupported claim that only the owner can
recover it. Health observation does not replace a full source/member verifier or
prove every dependent was adopted; inspect the propagation result and live release
evidence for that conclusion.

# s212 Azure Run Command guest-status defect handoff

## Identity and authority

- Project: `rexcoleman.dev`, s212 whole-arc WEA credential-recovery rail.
- Branch: `coach/s212-azure-status-fix`, based on `origin/main` at `2ef531f842d8c4d878d13ca8f0ec0de4a58adf78`.
- Parent authority: kernel-coach downstream repair dispatch for the source-level Azure Run Command validation defect.
- Boundary: source, tests, documentation, and convergence inventory only. This repair did not change live credentials, GitHub environment rows, an owner payload, or execute the recovery rail.

## Outcome

The rail now treats Azure CLI process success and `ProvisioningState/succeeded` as transport-level evidence only. Each Azure root script is bound to a SHA-256-derived in-guest success sentinel. Completion requires that exact sentinel as a complete output line in Azure's JSON response. The rail also performs an independent final comparison of the local root-owned approver public key against the hosted approver public-digest variable after the hosted probe passes.

## Root cause and measured evidence

`azure_root()` previously delegated to the generic subprocess helper and discarded the returned JSON. That helper proved only that the local `az` process exited zero. A safe, nonmutating planted reproduction invoked guest script `exit 41`; `azure_root()` returned normally and the caller observed `BUG_REPRO_AZURE_ROOT_ACCEPTED_EXIT_41` with process exit zero.

The direct Azure response for that planted guest failure had this captured shape:

```json
{
  "value": [
    {
      "code": "ProvisioningState/succeeded",
      "displayStatus": "Provisioning succeeded",
      "level": "Info",
      "message": "Enable succeeded: \n[stdout]\n\n[stderr]\n",
      "time": null
    }
  ]
}
```

Thus checking Azure's status field alone would preserve the defect. The repair requires rail-owned evidence that execution reached the end of the exact guest script. Re-running the nonmutating `exit 41` reproduction against the repaired source produced the expected `AZURE_RUN_COMMAND_GUEST_REFUSED` refusal.

The hosted principal probe compares the hosted private key with the hosted public-digest variable, but a hosted runner cannot observe the fixed public-key path on `gios-dev`. It therefore could pass while the local root-owned public key remained a predecessor. The new final postcheck closes that split by independently re-reading both sides.

## Changed surfaces

- `.github/write-enforcement/s212_wea_credential_recovery.py`: script-bound Azure sentinel validation and final local-public-key/hosted-variable comparison.
- `.github/write-enforcement/tests/test_s212_wea_credential_recovery.py`: captured outer-success/guest-failure polarity, exact sentinel polarity, guarded-script integration, and final digest-match polarity.
- `.github/write-enforcement/WEA_CREDENTIAL_RECOVERY.md`: whole-arc and refusal semantics.
- `.github/write-enforcement/signed_release_convergence_inventory.json`: discoverable source and planted-test markers while retaining all registered properties.

## Validation

- Focused s212 suite: 24 passed.
- Related write-enforcement suites: 209 passed.
- Complete `.github/write-enforcement/tests` collection: 698 collected; 697 passed and 1 skipped; exit zero.
- Convergence self-test: `SELF_TEST_PASS checks=9`.
- `PYTHONDONTWRITEBYTECODE=1` was set for Python test execution.
- Diff whitespace validation passed; no bytecode cache was left under `.github/write-enforcement`.

## Dispatch-probe review

No retry was added. The three inspected workflow dispatches all produced a run in the same second as dispatch, and current source already binds lookup to its nonce/title. There was no observed missing-run condition supporting a source change; adding a retry would have been conjectural.

## Live-state boundary

The parent reported the reconciled live state as: local root public SHA-256 `d65377441a09ae8582bb5c423a91ea4cb9a245b5277dd0bcaa69e8da11ae49a6`, predecessor backup absent, hosted secret present, hosted variables matching, and hosted approver principal passing. This source-only unit did not re-measure or mutate that state.

## Owner action

No owner action exists for this source repair. No owner command or opener was created.

### GPL-47: What This Does NOT Prove

The unit tests prove parsing/refusal polarity and ordering with controlled inputs; they do not authorize a live credential mutation. The captured Azure response establishes the actual outer-success/guest-failure behavior, but does not prove every Azure agent version reports failures identically. The final local comparison proves equality at the moment it runs, not future credential persistence. Publication checks and protected-branch ancestry must still be recorded in the final integrity envelope after publication.

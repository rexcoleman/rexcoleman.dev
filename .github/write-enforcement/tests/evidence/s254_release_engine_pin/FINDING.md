# s254 exact-plan release engine pin invariant

Date: 2026-09-29 UTC. Scope: shared release source in `rexcoleman.dev`; no release was issued, finalized, repointed, or installed.

The registered exact-plan adapter is `.github/write-enforcement/adapters/research_enforcement_activation.exact-plan-recovery-drive-v1.json`. Its `signed_release_convergence.py` route runs `build_frozen_manifest.py` twice (`manifest-a` and `manifest-b`), compares deterministic outputs, then records the exact-plan recovery snapshot before a manifest PR. The builder previously checked each selected member's bytes and remote reachability separately. It never compared the REA governance `govml_lock_commit` with the selected govML member commit, so deterministic rebuilds could both pass with a mutually incompatible pair.

The already frozen generation-5 manifest on `rexcoleman.dev` main has REA member commit `3819e9dd5eca5f25fffa37b0a302ea9b424d1f11` and govML member commit `07cb9b4a3d5fe76e0673cd43a2caa7623e8c40d8`. The committed REA governance at that REA commit pins `7bee6abc7a7d96488313457cd3981ca92a9bd0aa`. The new check refuses that exact pair. Raw reproduction: `r3_pin_refusal.raw.txt`.

`build_frozen_manifest.py` now reads `governance.yaml` from the selected immutable REA commit and compares its one canonical top-level `govml_lock_commit` with the govML commit that all selected govML members use. It refuses absent, malformed, duplicate, dirty, or different pins before opening the frozen population. It accepts an exact plain or quoted 40-character lowercase hex pin. The check runs for production and staged contracts; synthetic repository fixture contracts remain isolated from the five-repository release rule.

The focused tests prove a matching pair passes; planted mismatch, absent, malformed, duplicate, nested and dirty pins refuse; and builder entry checks the pin before opening any frozen member. Raw targeted result: `targeted_tests.raw.txt`, 11 passed. The full builder suite: `full_builder_tests.raw.txt`, 59 passed. Both exited 0. No installed gate or authority packet was edited.

This prevention applies to future plan construction. It does not retroactively change the already issued generation-5 release or authorize a second release.

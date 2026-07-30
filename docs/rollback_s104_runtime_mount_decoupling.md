# Rollback: installed REA authority binding

The original s104 repair replaced the production-site dependency on the
`~/research_enforcement_activation` working tree with the governed installed
runtime consumer. The s123 C3 integration preserves that boundary while
promoting the route-owned BLG-08/DST-02 exact-bundle consumer: production
authority now comes only from the fixed installed verify-only provider at:

`~/.local/libexec/rea_enforcement/hybrid_capability_provider`

If this route-owned consumer causes a production regression, revert the C3
integration commit as one unit. Do not point the site at an arbitrary checkout
or restore the PR's stale Moonshots-control pin as an operational workaround.
Publication must remain refused until either the revert is reviewed and merged
or the installed provider is repaired and its exact bytes are redeployed.

The production wrapper has no environment or caller-controlled provider,
runtime-module, callback, destination, command, or execution-context override.
Isolated tests may monkeypatch module constants only inside the test process;
that seam does not exist in the production entrypoint.

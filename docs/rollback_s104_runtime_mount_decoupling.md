# Rollback: installed REA runtime mount

This prepared change replaces the production-site dependency on the
`~/research_enforcement_activation` working tree with the governed installed
consumer at:

`/home/azureuser/.local/libexec/rea_enforcement/runtime_mount.py`

If the installed consumer causes a production regression, revert the commit
containing this file and `scripts/blog_publish_mount.py` together. Do not point
the site at an arbitrary checkout as an operational workaround. Publication
must remain refused until either the revert is reviewed and merged or the
installed consumer is repaired and its exact bytes are redeployed.

The `REA_WRITE_INTEGRITY_ISOLATED_RUNTIME_MOUNT` override is accepted only when
the explicit isolated hybrid context is also present. It exists for scratch
integration tests and is not a production override.

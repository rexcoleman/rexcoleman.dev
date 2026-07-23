"""Immutable generation-3 member and ruleset contract required before signing."""

import re


AUTHORITY_GENERATION = 3
GENERATION_MANIFEST_NAME = "frozen_bundle_manifest.generation-3.json"
RULESET_ID = 19564990
RULESET_FIELDS = (
    "name", "target", "enforcement", "conditions", "rules", "bypass_actors",
)


def generation_tag(commit: str) -> str:
    """Derive the one generation-3 tag name from the later manifest commit."""
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("generation tag commit")
    return f"rea-wea-generation-{AUTHORITY_GENERATION}-{commit[:12]}"


def normalize_ruleset(value: dict) -> dict:
    """Return only cryptographically covered fields, refusing an elided response."""
    if not isinstance(value, dict) or value.get("id") != RULESET_ID:
        raise ValueError(f"ruleset {RULESET_ID} unavailable")
    missing = sorted(set(RULESET_FIELDS) - set(value))
    if missing:
        raise ValueError(f"ruleset response missing capability-gated fields: {missing}")
    expected_types = {
        "name": str,
        "target": str,
        "enforcement": str,
        "conditions": dict,
        "rules": list,
        "bypass_actors": list,
    }
    wrong = sorted(key for key, expected in expected_types.items()
                   if not isinstance(value[key], expected))
    if wrong:
        raise ValueError(f"ruleset response field shape: {wrong}")
    return {key: value[key] for key in RULESET_FIELDS}

EXPECTED_MEMBERS = {
    # Authority, schemas, resolver, gates, and canonical consumer.
    "verify-only-resolver": ("research_enforcement_activation", "write_integrity/attestation/wea_verifier.py"),
    "claim-policy": ("research_enforcement_activation", "write_integrity/authority/claim_policy.json"),
    "claim-registry": ("research_enforcement_activation", "write_integrity/authority/claim_registry.json"),
    "authority-manifest": ("research_enforcement_activation", "write_integrity/authority/authority_manifest.json"),
    "authority-resolver": ("research_enforcement_activation", "write_integrity/authority/resolve_authority.py"),
    "authority-library": ("research_enforcement_activation", "write_integrity/authority/authority_lib.py"),
    "admission-library": ("research_enforcement_activation", "write_integrity/authority/admission_lib.py"),
    "cle-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/claim_lineage_envelope.schema.json"),
    "subject-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/exact_subject_tuple.schema.json"),
    "wea-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/write_enforcement_attestation.schema.json"),
    "profile-registry": ("research_enforcement_activation", "write_integrity/foundation/publishing_capability_profiles.json"),
    "route-inventory": ("research_enforcement_activation", "write_integrity/foundation/route_inventory.json"),
    "surface-gate-common": ("research_enforcement_activation", "write_integrity/gates/surface_gate.py"),
    "surface-gate-report": ("research_enforcement_activation", "write_integrity/gates/report_gate.py"),
    "surface-gate-blog": ("research_enforcement_activation", "write_integrity/gates/blog_gate.py"),
    "surface-gate-publication": ("research_enforcement_activation", "write_integrity/gates/publication_gate.py"),
    "surface-gate-distribution": ("research_enforcement_activation", "write_integrity/gates/distribution_gate.py"),
    "gate-token-engine": ("research_enforcement_activation", "write_integrity/gates/gate_lib.py"),
    "atomic-consumer": ("research_enforcement_activation", "write_integrity/consumer/atomic_consumer.py"),
    "route-runtime-mount": ("research_enforcement_activation", "write_integrity/mounts/runtime_mount.py"),
    "subject-runner": ("research_enforcement_activation", "write_integrity/runners/subject_runner.py"),
    # govML scaffold/runner activation and route-owned files from the accepted 22-file census.
    "trusted-public-key": ("govML", "templates/build/enforcement/trusted_wea_public.pem"),
    "scaffold-verifier": ("govML", "templates/build/enforcement/write_enforcement_state.py"),
    "scaffold-installer": ("govML", "templates/build/enforcement/install_write_enforcement.py"),
    "scaffold-transform": ("govML", "templates/build/enforcement/write_scaffold_transform.py"),
    "scaffold-atomic-runtime": ("govML", "templates/build/enforcement/scaffold_atomic_runtime.py"),
    "govml-init": ("govML", "scripts/init_project.sh"),
    "master-runner": ("govML", "scripts/check_all_gates.sh"),
    "project-runner": ("govML", "templates/build/enforcement/project_run_gates.sh"),
    "project-runner-f07": ("govML", "templates/build/enforcement/project_run_gates_F07.sh"),
    "project-runner-f08": ("govML", "templates/build/enforcement/project_run_gates_F08.sh"),
    "project-runner-f09": ("govML", "templates/build/enforcement/project_run_gates_F09.sh"),
    "write-boundary": ("govML", "templates/build/enforcement/write_boundary_gate.sh"),
    "write-readiness": ("govML", "templates/build/enforcement/write_publish_readiness.py"),
    "write-side-arm": ("govML", "templates/build/enforcement/write_side_arm.py"),
    "route-blog-wrapper": ("govML", "scripts/generators/blog_runtime_mount.py"),
    "route-report": ("govML", "scripts/generators/gen_research_report.py"),
    "route-publication": ("govML", "scripts/generators/gen_newsletter_issue.py"),
    "route-blog-01": ("govML", "scripts/generators/gen_blog_post.py"),
    "route-blog-02": ("govML", "scripts/generators/gen_paper_analysis.py"),
    "route-blog-03": ("govML", "scripts/generators/gen_methodology_overview.py"),
    "route-blog-04": ("govML", "scripts/generators/gen_experiment_learning.py"),
    "route-blog-05": ("govML", "scripts/generators/gen_market_signal.py"),
    "route-blog-06": ("govML", "scripts/generators/content_remediate.py"),
    "route-blog-07": ("govML", "scripts/generators/blog_publish_mount.py"),
    "route-distribution-01": ("govML", "scripts/generators/gen_distribution_kit.py"),
    # Moonshots route-owned files from the same census plus scaffolder/remote control.
    "research-scaffolder": ("Moonshots_Career_Thesis_v2", "scripts/scaffold_research_project.py"),
    "route-distribution-wrapper": ("Moonshots_Career_Thesis_v2", "scripts/write_integrity_mount.py"),
    "route-distribution-main": ("Moonshots_Career_Thesis_v2", "scripts/distribute.py"),
    "route-review-queue": ("Moonshots_Career_Thesis_v2", "scripts/review_queue.py"),
    "route-draft-engagement": ("Moonshots_Career_Thesis_v2", "scripts/draft_engagement.py"),
    "route-mark-published": ("Moonshots_Career_Thesis_v2", "scripts/mark_issue_published.py"),
    "route-prepare-experiment": ("Moonshots_Career_Thesis_v2", "scripts/prepare_experiment.py"),
    "route-log-rex-action": ("Moonshots_Career_Thesis_v2", "scripts/log_rex_action.py"),
    "route-buffer": ("Moonshots_Career_Thesis_v2", "scripts/buffer_publish.py"),
    "distribution-validator": ("Moonshots_Career_Thesis_v2", "scripts/validate_distribution.py"),
    "remote-reusable-workflow": ("Moonshots_Career_Thesis_v2", ".github/workflows/newsletter-integrity-authority.yml"),
    # Shipping remote check and its second pinned key copy.
    "newsletter-caller-workflow": ("newsletter", ".github/workflows/newsletter-integrity.yml"),
    "newsletter-remote-validator": ("newsletter", ".github/integrity/newsletter/validate_newsletter_commit.py"),
    "newsletter-trusted-public-key": ("newsletter", ".github/integrity/wea/trusted_wea_public.pem"),
    # rex route-owned files and protected issuer/hosted authority.
    "route-cross-post": ("rexcoleman.dev", "cross-post.py"),
    "route-publish-hugo": ("rexcoleman.dev", "publish.sh"),
    "remote-issuer-workflow": ("rexcoleman.dev", ".github/workflows/issue-write-enforcement-attestation.yml"),
    "remote-issuer": ("rexcoleman.dev", ".github/write-enforcement/issue_wea.py"),
    "remote-checkout": ("rexcoleman.dev", ".github/write-enforcement/checkout_manifest.py"),
    "remote-manifest-builder": ("rexcoleman.dev", ".github/write-enforcement/build_frozen_manifest.py"),
    "remote-member-contract": ("rexcoleman.dev", ".github/write-enforcement/member_contract.py"),
    "remote-freeze-sequence": ("rexcoleman.dev", ".github/write-enforcement/FREEZE_SEQUENCE.md"),
    "generation-2-owner-runbook": ("rexcoleman.dev", ".github/write-enforcement/GENERATION_2_OWNER_RUNBOOK.md"),
    "generation-3-owner-runbook": ("rexcoleman.dev", ".github/write-enforcement/GENERATION_3_OWNER_RUNBOOK.md"),
    "hosted-wea-verifier": ("rexcoleman.dev", ".github/write-enforcement/verify_hosted_wea.py"),
    "hosted-wea-workflow": ("rexcoleman.dev", ".github/workflows/verify-write-enforcement.yml"),
    "hosted-blog-deploy": ("rexcoleman.dev", ".github/workflows/deploy.yml"),
    "hosted-sealed-verifier": ("rexcoleman.dev", ".github/research-integrity/verify_sealed_authority.py"),
}

ROUTE_OWNED_MEMBER_IDS = {
    "route-runtime-mount", "route-blog-wrapper", "route-report", "route-publication",
    "route-blog-01", "route-blog-02", "route-blog-03", "route-blog-04", "route-blog-05",
    "route-blog-06", "route-blog-07", "route-distribution-01", "route-distribution-wrapper",
    "route-distribution-main", "route-review-queue", "route-draft-engagement",
    "route-mark-published", "route-prepare-experiment", "route-log-rex-action", "route-buffer",
    "route-cross-post", "route-publish-hugo",
}


def grouped_members():
    grouped = {}
    for member_id, (repository, path) in EXPECTED_MEMBERS.items():
        grouped.setdefault(repository, []).append((member_id, path))
    return {repository: tuple(rows) for repository, rows in grouped.items()}

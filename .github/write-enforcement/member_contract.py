"""Immutable generation-4 member and ruleset contract required before signing."""

import hashlib
import json
import re


AUTHORITY_GENERATION = 4
GENERATION_MANIFEST_NAME = "frozen_bundle_manifest.generation-4.json"
RULESET_ID = 19564990
RULESET_FIELDS = (
    "name", "target", "enforcement", "conditions", "rules", "bypass_actors",
)
REQUIRED_MEMBER_CLASSES = (
    "boundary_gate",
    "resolver",
    "readiness_consumer",
    "live_emitter_binding",
    "master_runner_binding",
    "project_runner_binding",
    "scaffold_installer",
    "invocation_receipt",
    "close_readiness_gate",
    "remote_workflow",
    "remote_ruleset",
    "claim_policy",
    "profile_registry",
    "trusted_public_key",
)

WRITE_BOUNDARY_POLICY_MEMBERS = (
    ("write-boundary-engine", "write_integrity/write_boundary/boundary_engine.py"),
    ("write-boundary-trusted-admission", "write_integrity/write_boundary/trusted_admission.py"),
    ("write-boundary-row-registry", "write_integrity/write_boundary/row_registry.json"),
    ("write-boundary-seam-registry", "write_integrity/write_boundary/seam_registry.json"),
    ("write-boundary-transform-registry", "write_integrity/write_boundary/transform_registry.json"),
    ("write-boundary-request-schema", "write_integrity/write_boundary/schemas/request.schema.json"),
    ("write-boundary-parent-admission-schema", "write_integrity/write_boundary/schemas/parent_admission.schema.json"),
    ("write-boundary-receipt-schema", "write_integrity/write_boundary/schemas/receipt.schema.json"),
    ("write-boundary-ledger-schema", "write_integrity/write_boundary/schemas/ledger.schema.json"),
)
WRITE_BOUNDARY_SURFACES = frozenset({"report", "blog", "publication", "distribution"})
WRITE_BOUNDARY_CANONICAL_ACTOR_COUNT = 29
WRITE_BOUNDARY_SEAM_COUNT = 10
WRITE_BOUNDARY_ROW_COUNT = 44
WRITE_BOUNDARY_ALIASES = {"RPT-01A": "RPT-01"}
SIGNED_SCAFFOLD_MEMBER_IDS = frozenset({
    "scaffold-hybrid-route-consumer",
    "scaffold-hybrid-install-manifest",
})


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_boundary_policy_digest(loaded: dict[str, bytes]) -> str:
    """Hash only the nine already-verified committed policy member bytes."""
    hashes = {}
    for member_id, relative in WRITE_BOUNDARY_POLICY_MEMBERS:
        raw = loaded.get(member_id)
        if not isinstance(raw, bytes):
            raise ValueError(f"write-boundary policy member unavailable: {member_id}")
        hashes[relative] = digest(raw)
    return digest(canonical(hashes))


def derive_write_boundary_route_surface_bindings(
    row_registry_raw: bytes, seam_registry_raw: bytes
) -> dict[str, str | list[str]]:
    """Derive the closed runtime route/surface map from verified registry bytes."""
    row_registry = json.loads(row_registry_raw)
    seam_registry = json.loads(seam_registry_raw)
    if not isinstance(row_registry, dict) or not isinstance(seam_registry, dict):
        raise ValueError("write-boundary registry shape")
    population = row_registry.get("population")
    actors = row_registry.get("canonical_actor_ids")
    aliases = row_registry.get("aliases")
    rows = row_registry.get("rows")
    seams = seam_registry.get("seams")
    if (
        row_registry.get("schema_version") != "rea.write-boundary.row-registry.v1"
        or seam_registry.get("schema_version") != "rea.write-boundary.seam-registry.v1"
        or population != {
            "first_path_id": "F22", "last_path_id": "F65", "expected_count": 44
        }
        or aliases != WRITE_BOUNDARY_ALIASES
        or not isinstance(actors, list)
        or len(actors) != WRITE_BOUNDARY_CANONICAL_ACTOR_COUNT
        or len(set(actors)) != len(actors)
        or "RPT-01A" in actors
        or not all(isinstance(actor, str) and actor for actor in actors)
        or not isinstance(rows, list)
        or len(rows) != WRITE_BOUNDARY_ROW_COUNT
        or not isinstance(seams, list)
        or len(seams) != WRITE_BOUNDARY_SEAM_COUNT
    ):
        raise ValueError("write-boundary registry closure")

    expected_paths = {f"F{number}" for number in range(22, 66)}
    observed_paths: set[str] = set()
    actor_surfaces = {actor: set() for actor in actors}
    actorless_paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("write-boundary row shape")
        path_id = row.get("path_id")
        surface = row.get("surface")
        row_actors = row.get("actor_ids")
        if (
            path_id not in expected_paths
            or path_id in observed_paths
            or surface not in WRITE_BOUNDARY_SURFACES
            or not isinstance(row_actors, list)
            or len(row_actors) != len(set(row_actors))
            or any(actor not in actor_surfaces for actor in row_actors)
        ):
            raise ValueError("write-boundary row closure")
        observed_paths.add(path_id)
        if row_actors:
            for actor in row_actors:
                actor_surfaces[actor].add(surface)
        else:
            actorless_paths.add(path_id)
    if observed_paths != expected_paths or any(not surfaces for surfaces in actor_surfaces.values()):
        raise ValueError("write-boundary row population")

    seam_surfaces: dict[str, set[str]] = {}
    seam_paths: set[str] = set()
    row_surfaces = {row["path_id"]: row["surface"] for row in rows}
    for seam in seams:
        if not isinstance(seam, dict):
            raise ValueError("write-boundary seam shape")
        path_id = seam.get("path_id")
        seam_id = seam.get("seam_id")
        if (
            path_id not in actorless_paths
            or path_id in seam_paths
            or not isinstance(seam_id, str)
            or not seam_id
            or seam_id in seam_surfaces
        ):
            raise ValueError("write-boundary seam closure")
        seam_paths.add(path_id)
        seam_surfaces[seam_id] = {row_surfaces[path_id]}
    if seam_paths != actorless_paths:
        raise ValueError("write-boundary seam population")

    bindings: dict[str, str | list[str]] = {}
    for route, surfaces in {
        **actor_surfaces,
        **{f"SEAM:{seam}": value for seam, value in seam_surfaces.items()},
    }.items():
        ordered = sorted(surfaces)
        bindings[route] = ordered[0] if len(ordered) == 1 else ordered
    if (
        len(bindings) != WRITE_BOUNDARY_CANONICAL_ACTOR_COUNT + WRITE_BOUNDARY_SEAM_COUNT
        or "RPT-01A" in bindings
        or bindings.get("PUB-04") != ["publication", "report"]
        or bindings.get("DST-02") != "blog"
    ):
        raise ValueError("write-boundary route closure")
    return bindings


def generation_tag(commit: str) -> str:
    """Derive the one generation-4 tag name from the later manifest commit."""
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
    "wea-lifetime-library": ("research_enforcement_activation", "write_integrity/attestation/lifetime.py"),
    "r4-plan-builder": ("research_enforcement_activation", "write_integrity/attestation/build_r4_plan.py"),
    "r4-matrix-harness": ("research_enforcement_activation", "write_integrity/attestation/run_r4_matrix.py"),
    "r4-harness-common": ("research_enforcement_activation", "write_integrity/attestation/harness_common.py"),
    "r4-actor-probe": ("research_enforcement_activation", "write_integrity/attestation/r4_actor_probe.py"),
    "r4-actor-inventory": ("research_enforcement_activation", "write_integrity/attestation/r4_actor_inventory.json"),
    "coverage-registry-library": ("research_enforcement_activation", "write_integrity/coverage_registry.py"),
    "close-accounting-gate": ("research_enforcement_activation", "write_integrity/close_accounting_gate.py"),
    "claim-policy": ("research_enforcement_activation", "write_integrity/authority/claim_policy.json"),
    "claim-registry": ("research_enforcement_activation", "write_integrity/authority/claim_registry.json"),
    "authority-manifest": ("research_enforcement_activation", "write_integrity/authority/authority_manifest.json"),
    "authority-resolver": ("research_enforcement_activation", "write_integrity/authority/resolve_authority.py"),
    "authority-library": ("research_enforcement_activation", "write_integrity/authority/authority_lib.py"),
    "authority-generated-constants": ("research_enforcement_activation", "write_integrity/authority/generated_constants.py"),
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
    "hybrid-capability-provider": ("research_enforcement_activation", "write_integrity/hybrid/capability_provider.py"),
    "route-runtime-mount": ("research_enforcement_activation", "write_integrity/mounts/runtime_mount.py"),
    "write-boundary-engine": ("research_enforcement_activation", "write_integrity/write_boundary/boundary_engine.py"),
    "write-boundary-trusted-admission": ("research_enforcement_activation", "write_integrity/write_boundary/trusted_admission.py"),
    "write-boundary-row-registry": ("research_enforcement_activation", "write_integrity/write_boundary/row_registry.json"),
    "write-boundary-seam-registry": ("research_enforcement_activation", "write_integrity/write_boundary/seam_registry.json"),
    "write-boundary-transform-registry": ("research_enforcement_activation", "write_integrity/write_boundary/transform_registry.json"),
    "write-boundary-request-schema": ("research_enforcement_activation", "write_integrity/write_boundary/schemas/request.schema.json"),
    "write-boundary-parent-admission-schema": ("research_enforcement_activation", "write_integrity/write_boundary/schemas/parent_admission.schema.json"),
    "write-boundary-receipt-schema": ("research_enforcement_activation", "write_integrity/write_boundary/schemas/receipt.schema.json"),
    "write-boundary-ledger-schema": ("research_enforcement_activation", "write_integrity/write_boundary/schemas/ledger.schema.json"),
    "wea-consumer": ("research_enforcement_activation", "write_integrity/attestation/wea_consumer.py"),
    "subject-runner": ("research_enforcement_activation", "write_integrity/runners/subject_runner.py"),
    "runner-adapter": ("research_enforcement_activation", "write_integrity/runners/runner_adapter.py"),
    # Accepted s88 Face A production request provisioner and its closed inputs.
    "production-package-init": ("research_enforcement_activation", "write_integrity/provisioning/__init__.py"),
    "production-request-provisioner": ("research_enforcement_activation", "write_integrity/provisioning/prp.py"),
    "production-boundary": ("research_enforcement_activation", "write_integrity/provisioning/boundary.py"),
    "production-fixed-adapter": ("research_enforcement_activation", "write_integrity/provisioning/fixed_adapter.py"),
    "production-request-cli": ("research_enforcement_activation", "write_integrity/provisioning/production_request.py"),
    "production-staging": ("research_enforcement_activation", "write_integrity/provisioning/staging.py"),
    "route-class-authority-map": ("research_enforcement_activation", "write_integrity/foundation/route_class_authority_map.json"),
    "production-event-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/production_event.schema.json"),
    "production-request-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/production_request.schema.json"),
    "route-class-authority-map-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/route_class_authority_map.schema.json"),
    "staging-creation-receipt-schema": ("research_enforcement_activation", "write_integrity/foundation/schemas/staging_creation_receipt.schema.json"),
    # Accepted s88 Face B successor-subject machinery and its isolated fixture.
    # The fixture is bundle-covered evidence tooling, not a deployed protected
    # Research Close entrypoint. Unit-test files remain outside the bundle.
    "successor-subject-package-init": ("research_enforcement_activation", "write_integrity/authority/successor_subject/__init__.py"),
    "successor-subject-protocol": ("research_enforcement_activation", "write_integrity/authority/successor_subject/protocol.py"),
    "successor-subject-isolated-fixture": ("research_enforcement_activation", "write_integrity/authority/successor_subject/run_fixture.py"),
    "successor-subject-face-a-b5-isolated-helper": ("research_enforcement_activation", "write_integrity/authority/successor_subject/face_a_b5_fixture.py"),
    "successor-admission-record-schema": ("research_enforcement_activation", "write_integrity/authority/successor_subject/schemas/admission_record.schema.json"),
    "successor-close-receipt-schema": ("research_enforcement_activation", "write_integrity/authority/successor_subject/schemas/close_receipt.schema.json"),
    "successor-protected-transition-schema": ("research_enforcement_activation", "write_integrity/authority/successor_subject/schemas/protected_transition.schema.json"),
    "successor-event-schema": ("research_enforcement_activation", "write_integrity/authority/successor_subject/schemas/successor_event.schema.json"),
    "successor-update-declaration-schema": ("research_enforcement_activation", "write_integrity/authority/successor_subject/schemas/update_declaration.schema.json"),
    # govML scaffold/runner activation and route-owned files from the accepted 22-file census.
    "trusted-public-key": ("govML", "templates/build/enforcement/trusted_wea_public.pem"),
    "scaffold-verifier": ("govML", "templates/build/enforcement/write_enforcement_state.py"),
    "scaffold-installer": ("govML", "templates/build/enforcement/install_write_enforcement.py"),
    "scaffold-hybrid-route-consumer": ("govML", "templates/build/enforcement/hybrid_route_consumer.py"),
    "scaffold-hybrid-install-manifest": ("govML", "templates/build/enforcement/hybrid_install_manifest.json"),
    "scaffold-transform": ("govML", "templates/build/enforcement/write_scaffold_transform.py"),
    "scaffold-atomic-runtime": ("govML", "templates/build/enforcement/scaffold_atomic_runtime.py"),
    "govml-init": ("govML", "scripts/init_project.sh"),
    "master-runner": ("govML", "scripts/check_all_gates.sh"),
    "project-runner": ("govML", "templates/build/enforcement/project_run_gates.sh"),
    "project-runner-f07": ("govML", "templates/build/enforcement/project_run_gates_F07.sh"),
    "project-runner-f08": ("govML", "templates/build/enforcement/project_run_gates_F08.sh"),
    "project-runner-f09": ("govML", "templates/build/enforcement/project_run_gates_F09.sh"),
    "runner-adapter-launcher": ("govML", "templates/build/enforcement/runner_adapter_launcher.py"),
    "gate-invocation-receipt": ("govML", "templates/build/enforcement/gate_invocation_receipt.py"),
    "enforcement-fired-gate": ("govML", "templates/build/enforcement/enforcement_fired_gate.sh"),
    "write-boundary": ("govML", "templates/build/enforcement/write_boundary_gate.sh"),
    "write-readiness": ("govML", "templates/build/enforcement/write_publish_readiness.py"),
    "write-side-arm": ("govML", "templates/build/enforcement/write_side_arm.py"),
    "route-blog-wrapper": ("govML", "scripts/generators/blog_runtime_mount.py"),
    "route-report": ("govML", "scripts/generators/gen_research_report.py"),
    "route-publication-wrapper": ("govML", "scripts/generators/hybrid_publish_mount.py"),
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
    "generation-4-owner-runbook": ("rexcoleman.dev", ".github/write-enforcement/GENERATION_4_OWNER_RUNBOOK.md"),
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

FACE_A_MEMBER_IDS = {
    "production-package-init",
    "production-request-provisioner",
    "production-boundary",
    "production-fixed-adapter",
    "production-request-cli",
    "production-staging",
    "route-class-authority-map",
    "production-event-schema",
    "production-request-schema",
    "route-class-authority-map-schema",
    "staging-creation-receipt-schema",
}

FACE_B_MEMBER_IDS = {
    "successor-subject-package-init",
    "successor-subject-protocol",
    "successor-subject-isolated-fixture",
    "successor-subject-face-a-b5-isolated-helper",
    "successor-admission-record-schema",
    "successor-close-receipt-schema",
    "successor-protected-transition-schema",
    "successor-event-schema",
    "successor-update-declaration-schema",
}

FACE_B_ISOLATED_FIXTURE_MEMBER_IDS = {
    "successor-subject-isolated-fixture",
    "successor-subject-face-a-b5-isolated-helper",
}

S88_BUNDLE_MEMBER_IDS = (
    FACE_A_MEMBER_IDS
    | FACE_B_MEMBER_IDS
    | {
        "authority-library", "verify-only-resolver", "wea-lifetime-library",
        "coverage-registry-library", "close-accounting-gate",
    }
)


def grouped_members():
    grouped = {}
    for member_id, (repository, path) in EXPECTED_MEMBERS.items():
        grouped.setdefault(repository, []).append((member_id, path))
    return {repository: tuple(rows) for repository, rows in grouped.items()}

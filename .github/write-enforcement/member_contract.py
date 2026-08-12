"""Immutable active and historical member contracts required before signing."""

from __future__ import annotations

import ast
import hashlib
import json
import re


HISTORICAL_AUTHORITY_GENERATION = 4
HISTORICAL_GENERATION_MANIFEST_NAME = "frozen_bundle_manifest.generation-4.json"
AUTHORITY_GENERATION = 5
GENERATION_MANIFEST_NAME = "frozen_bundle_manifest.generation-5.json"
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
ROW_COMPLETE_PACKAGE_MEMBER_IDS = frozenset({
    "row-complete-full-receipts",
    "row-complete-ledger",
    "row-complete-ancestry-attestation",
})
SIGNED_SCAFFOLD_MEMBER_IDS = frozenset({
    "scaffold-hybrid-route-consumer",
    "scaffold-hybrid-install-manifest",
    "scaffold-hybrid-core-atomic-consumer",
    "scaffold-hybrid-core-package-init",
    "scaffold-hybrid-core-durable-spend",
    "scaffold-hybrid-core-jsonschema-compat",
    "scaffold-hybrid-core-protocol",
    "scaffold-hybrid-core-authorized-mapping-schema",
    "scaffold-hybrid-core-external-evidence-receipt-schema",
    "scaffold-hybrid-core-claim-lineage-schema",
    "scaffold-hybrid-core-project-close-receipt-schema",
    "scaffold-hybrid-core-revocation-registry-schema",
    "scaffold-hybrid-core-route-neutral-capability-schema",
    "scaffold-hybrid-core-trusted-issuer-schema",
    "scaffold-hybrid-core-runtime-mount",
    "scaffold-hybrid-core-provisioning-package-init",
    "scaffold-hybrid-core-provisioning-boundary",
    "scaffold-hybrid-core-provisioning-fixed-adapter",
    "scaffold-hybrid-core-provisioning-prp",
    "scaffold-hybrid-core-write-boundary-engine",
    "scaffold-hybrid-core-corpus-honest",
    "scaffold-hybrid-core-corpus-manifest",
    "scaffold-hybrid-core-corpus-planted",
    "scaffold-hybrid-core-protected-receive",
    "scaffold-hybrid-core-row-complete-verifier",
    *ROW_COMPLETE_PACKAGE_MEMBER_IDS,
    "scaffold-hybrid-core-row-registry",
    "scaffold-hybrid-core-ledger-schema",
    "scaffold-hybrid-core-parent-admission-schema",
    "scaffold-hybrid-core-receipt-schema",
    "scaffold-hybrid-core-request-schema",
    "scaffold-hybrid-core-seam-registry",
    "scaffold-hybrid-core-transform-registry",
    "scaffold-hybrid-core-trusted-admission",
    "scaffold-report-surface",
    "scaffold-report-auditor-generator",
    "canonical-exact-byte-handoff",
    "scaffold-report-orchestrator",
    "scaffold-wea-consumer",
})

# The installed project runner delegates to the signed master runner.  These
# are the complete direct and transitive files that make that delegation
# executable from the installed bundle rather than from a mutable govML
# working copy.  Keep the graph explicit: a flat population count previously
# admitted the master while omitting its mandatory children.
SIGNED_COMPLETE_CHAIN_MEMBER_IDS = frozenset({
    "master-pre-compute-check",
    "signed-hypothesis-gate",
    "master-readability-checker",
    "emitter-runtime-channel-voice-checker",
    "master-gate05",
    "master-gate05-scaffold",
    "master-handoff-scrutiny",
    "master-loop-exit",
    "master-file-re-reading",
    "master-readme-checker",
    "master-generalizability",
    "master-build-pipeline",
    "master-build-profile-gate-bundle",
    "canonical-enforcement-block",
    "canonical-agent-pre-check-runner",
    "canonical-research-integrity-checklist",
    "canonical-landscape-depth-f3",
    "canonical-landscape-depth-gate",
})
COMPLETE_CHAIN_DEPENDENCIES = {
    "master-pre-compute-check": frozenset({
        "signed-hypothesis-gate",
    }),
    "master-runner": frozenset({
        "master-pre-compute-check",
        "canonical-enforcement-block",
        "master-readability-checker",
        "emitter-runtime-channel-voice-checker",
        "master-gate05",
        "master-gate05-scaffold",
        "master-handoff-scrutiny",
        "master-loop-exit",
        "master-file-re-reading",
        "master-readme-checker",
        "master-generalizability",
        "master-build-pipeline",
        "master-build-profile-gate-bundle",
    }),
    "canonical-enforcement-block": frozenset({
        "canonical-agent-pre-check-runner",
        "canonical-research-integrity-checklist",
        "canonical-landscape-depth-f3",
    }),
    "canonical-landscape-depth-f3": frozenset({
        "canonical-landscape-depth-gate",
    }),
}
PACKAGED_BUILD_PROFILE_GATE_SOURCES = {
    "hc26": ("govML", "scripts/hc26_internal_smoke_gate.sh", 0o755),
    "k-register": ("govML", "scripts/k_register_present_gate.sh", 0o755),
    "known-boundaries": ("govML", "scripts/known_boundaries_present_gate.sh", 0o755),
    "h-pattern": ("govML", "scripts/h_pattern_dispositions_present_gate.sh", 0o755),
    "spec-implementation": ("govML", "scripts/spec_implementation_present_gate.sh", 0o755),
    "session-close": ("govML", "scripts/spec_implementation_session_close_gate.sh", 0o755),
}

# These procedures remain committed and reviewable on the exact
# rexcoleman.dev ref, but they are not consumed by the installed enforcement
# runtime. Every executable issuer and verifier source remains signed.
EXTERNAL_FREEZE_PROCEDURE_SUBJECT = (
    "rexcoleman.dev",
    ".github/write-enforcement/FREEZE_SEQUENCE.md",
)
EXTERNAL_GENERATION4_OWNER_RUNBOOK_SUBJECT = (
    "rexcoleman.dev",
    ".github/write-enforcement/GENERATION_4_OWNER_RUNBOOK.md",
)

# These generator sources are compared byte-for-byte with the signed installed
# copies at the same immutable govML commit.  Their installed identities remain
# in the production contract; a second member row for the authoring pathname is
# redundant and would displace runtime gates from the fixed population.
EXTERNAL_EMITTER_AUTHORING_SUBJECTS = {
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
    "emitter-runtime-sweep": ("govML", "scripts/generators/gen_sweep.py"),
    "emitter-runtime-manifest-verifier": (
        "govML", "scripts/generators/gen_manifest_verifier.py"
    ),
}


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
    """Derive the active-generation tag name from the later manifest commit."""
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
    "consumer-inventory": ("research_enforcement_activation", "write_integrity/attestation/consumer_inventory.json"),
    "write-side-ac-runner": ("research_enforcement_activation", "tests/write_integrity/run_ac_suite.sh"),
    "write-side-ac-suite": ("research_enforcement_activation", "tests/write_integrity/run_real_prose_ac.py"),
    "write-side-ac-verification-source": ("research_enforcement_activation", "tests/write_integrity/fixtures/s150_ac_sources/VERIFICATION.md"),
    "write-side-ac-findings-source": ("research_enforcement_activation", "tests/write_integrity/fixtures/s150_ac_sources/FINDINGS.md"),
    "write-side-ac-provenance-manifest": ("research_enforcement_activation", "tests/write_integrity/fixtures/s150_ac_sources/provenance_manifest.json"),
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
    "write-boundary-engine": ("govML", "templates/build/enforcement/signed_authoring/write_boundary_engine.py"),
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
    "production-request-provisioner": ("govML", "templates/build/enforcement/signed_authoring/production_request_provisioner.py"),
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
    # The installer consumes these vendored govML bytes. Their historical REA
    # provenance is not their comparison identity; the artifact under test is
    # the exact vendored path that will be installed.
    "scaffold-hybrid-core-atomic-consumer": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/consumer/atomic_consumer.py"),
    "scaffold-hybrid-core-package-init": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/__init__.py"),
    "scaffold-hybrid-core-durable-spend": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/durable_spend.py"),
    "scaffold-hybrid-core-jsonschema-compat": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/jsonschema_compat.py"),
    "scaffold-hybrid-core-protocol": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/protocol.py"),
    "scaffold-hybrid-core-authorized-mapping-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/authorized_mapping.schema.json"),
    "scaffold-hybrid-core-external-evidence-receipt-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/external_evidence_receipt.schema.json"),
    "scaffold-hybrid-core-claim-lineage-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/hybrid_claim_lineage.schema.json"),
    "scaffold-hybrid-core-project-close-receipt-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/project_close_receipt.schema.json"),
    "scaffold-hybrid-core-revocation-registry-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/revocation_registry.schema.json"),
    "scaffold-hybrid-core-route-neutral-capability-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/route_neutral_capability.schema.json"),
    "scaffold-hybrid-core-trusted-issuer-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/hybrid/schemas/trusted_issuer.schema.json"),
    "scaffold-hybrid-core-runtime-mount": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/mounts/runtime_mount.py"),
    "scaffold-hybrid-core-provisioning-package-init": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/provisioning/__init__.py"),
    "scaffold-hybrid-core-provisioning-boundary": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/provisioning/boundary.py"),
    "scaffold-hybrid-core-provisioning-fixed-adapter": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/provisioning/fixed_adapter.py"),
    "scaffold-hybrid-core-provisioning-prp": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/provisioning/prp.py"),
    "scaffold-hybrid-core-write-boundary-engine": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/boundary_engine.py"),
    "scaffold-hybrid-core-corpus-honest": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/corpus/honest.jsonl"),
    "scaffold-hybrid-core-corpus-manifest": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/corpus/manifest.json"),
    "scaffold-hybrid-core-corpus-planted": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/corpus/planted.jsonl"),
    "scaffold-hybrid-core-protected-receive": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/protected_receive.py"),
    "scaffold-hybrid-core-row-complete-verifier": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/row_complete_verifier.py"),
    "row-complete-full-receipts": ("govML", "templates/build/enforcement/row_complete/full-receipts.json"),
    "row-complete-ledger": ("govML", "templates/build/enforcement/row_complete/ledger.json"),
    "row-complete-ancestry-attestation": ("govML", "templates/build/enforcement/row_complete/ancestry-attestation.json"),
    "scaffold-hybrid-core-row-registry": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/row_registry.json"),
    "scaffold-hybrid-core-ledger-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/schemas/ledger.schema.json"),
    "scaffold-hybrid-core-parent-admission-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/schemas/parent_admission.schema.json"),
    "scaffold-hybrid-core-receipt-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/schemas/receipt.schema.json"),
    "scaffold-hybrid-core-request-schema": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/schemas/request.schema.json"),
    "scaffold-hybrid-core-seam-registry": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/seam_registry.json"),
    "scaffold-hybrid-core-transform-registry": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/transform_registry.json"),
    "scaffold-hybrid-core-trusted-admission": ("govML", "templates/build/enforcement/hybrid_core/write_integrity/write_boundary/trusted_admission.py"),
    "scaffold-report-surface": ("govML", "templates/build/enforcement/report_surface.py"),
    "scaffold-report-auditor-generator": ("govML", "scripts/generators/gen_report_auditor.py"),
    "canonical-exact-byte-handoff": ("govML", "templates/build/enforcement/exact_byte_handoff.py"),
    "scaffold-report-orchestrator": ("govML", "scripts/generators/orchestrate.py"),
    "scaffold-wea-consumer": ("govML", "templates/build/enforcement/write_enforcement_consumer.py"),
    "scaffold-transform": ("govML", "templates/build/enforcement/write_scaffold_transform.py"),
    "scaffold-atomic-runtime": ("govML", "templates/build/enforcement/scaffold_atomic_runtime.py"),
    "govml-init": ("govML", "scripts/init_project.sh"),
    "master-runner": ("govML", "scripts/check_all_gates.sh"),
    "master-pre-compute-check": ("govML", "scripts/pre_compute_check.sh"),
    "master-readability-checker": (
        "govML", "scripts/generators/gen_readability_check.py"
    ),
    "signed-hypothesis-gate": (
        "Moonshots_Career_Thesis_v2", "scripts/hypothesis_gate.sh"
    ),
    "canonical-enforcement-block": ("govML", "templates/build/enforcement/run_gates_enforcement_block.sh"),
    "canonical-agent-pre-check-runner": ("govML", "scripts/agent_pre_check_runner.sh"),
    "canonical-research-integrity-checklist": ("govML", "checklists/research_integrity.checklist"),
    "canonical-landscape-depth-f3": ("govML", "scripts/landscape_depth_gate_F3.sh"),
    "canonical-landscape-depth-gate": ("govML", "scripts/landscape_depth_gate.sh"),
    "master-gate05": ("govML", "scripts/check_gate05.sh"),
    "master-gate05-scaffold": ("govML", "scripts/check_gate05_scaffold.sh"),
    "master-handoff-scrutiny": ("govML", "scripts/handoff_scrutiny_gate.sh"),
    "master-loop-exit": ("govML", "scripts/loop_exit_gate.sh"),
    "master-file-re-reading": ("govML", "scripts/file_re_reading_gate.sh"),
    "master-readme-checker": ("govML", "scripts/generators/gen_readme.py"),
    "master-generalizability": ("govML", "scripts/check_generalizability.sh"),
    "master-build-pipeline": ("govML", "scripts/build_pipeline_gate.sh"),
    "master-build-profile-gate-bundle": (
        "govML",
        "templates/build/enforcement/installed_build_profile_gate_bundle.py",
    ),
    "quality-loop": ("govML", "scripts/quality_loop.sh"),
    "quality-semantic-review": ("govML", "scripts/semantic_review.py"),
    "quality-findings-audit-generator": ("govML", "scripts/generators/gen_findings_audit.py"),
    "project-runner": ("govML", "templates/build/enforcement/project_run_gates.sh"),
    "external-judge-authority-issuer": ("govML", "scripts/issue_external_judge_authority.py"),
    "external-judge-authority-verifier": ("govML", "scripts/external_judge_authority.py"),
    "external-judge-authority-judge": ("govML", "scripts/landscape_depth_judge.py"),
    "runner-adapter-launcher": ("govML", "templates/build/enforcement/runner_adapter_launcher.py"),
    "gate-invocation-receipt": ("govML", "templates/build/enforcement/gate_invocation_receipt.py"),
    "enforcement-fired-gate": ("govML", "templates/build/enforcement/enforcement_fired_gate.sh"),
    "write-boundary": ("govML", "templates/build/enforcement/write_boundary_gate.sh"),
    "write-readiness": ("govML", "templates/build/enforcement/write_publish_readiness.py"),
    "write-side-arm": ("govML", "templates/build/enforcement/write_side_arm.py"),
    "write-side-arm-recorder": ("govML", "templates/build/enforcement/record_write_side_validation.py"),
    # Moonshots route-owned files from the same census plus scaffolder/remote control.
    "research-scaffolder": ("Moonshots_Career_Thesis_v2", "scripts/scaffold_research_project.py"),
    "research-type-registration-validator": (
        "Moonshots_Career_Thesis_v2",
        "scripts/validate_research_type_registration.py",
    ),
    "research-type-stage-owner-grid": (
        "Moonshots_Career_Thesis_v2",
        ".claude/references/research_type_stage_artifact_owner_grid.json",
    ),
    "t3-score-engine": ("Moonshots_Career_Thesis_v2", "scripts/score_t3.py"),
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
    "newsletter-control-manifest": ("newsletter", ".github/integrity/newsletter/control-manifest.json"),
    "newsletter-trusted-public-key": ("newsletter", ".github/integrity/wea/trusted_wea_public.pem"),
    # rex route-owned files and protected issuer/hosted authority.
    "route-cross-post": ("rexcoleman.dev", "cross-post.py"),
    "route-publish-hugo": ("rexcoleman.dev", "publish.sh"),
    "remote-issuer-workflow": ("rexcoleman.dev", ".github/workflows/issue-write-enforcement-attestation.yml"),
    "remote-issuer": ("rexcoleman.dev", ".github/write-enforcement/issue_wea.py"),
    "remote-checkout": ("rexcoleman.dev", ".github/write-enforcement/checkout_manifest.py"),
    "remote-manifest-builder": ("rexcoleman.dev", ".github/write-enforcement/build_frozen_manifest.py"),
    "remote-member-contract": ("rexcoleman.dev", ".github/write-enforcement/member_contract.py"),
    "hosted-wea-verifier": ("rexcoleman.dev", ".github/write-enforcement/verify_hosted_wea.py"),
    "hosted-wea-workflow": ("rexcoleman.dev", ".github/workflows/verify-write-enforcement.yml"),
    "hosted-blog-deploy": ("rexcoleman.dev", ".github/workflows/deploy.yml"),
    "hosted-sealed-verifier": ("rexcoleman.dev", ".github/research-integrity/verify_sealed_authority.py"),
}

# Complete canonical installation population.  These rows are kept explicit in
# the remote contract (rather than discovered from a mutable checkout) while
# `managed_enforcement_inventory.py` provides the independent installer-side
# enumeration.  Freeze tests require exact equality between both populations.
EXPECTED_MEMBERS.update({
    "managed-artifact-class-integrity": ("govML", "templates/build/enforcement/artifact_class_integrity.py"),
    "managed-artifact-class-registry": ("govML", "templates/build/enforcement/artifact_class_registry.json"),
    "managed-artifact-integrity-effect-gate": ("govML", "templates/build/enforcement/artifact_integrity_effect_gate.py"),
    "managed-artifact-hard-slots": ("govML", "templates/build/enforcement/artifact_integrity_hard_slot_dispositions.json"),
    "managed-artifact-integrity-manifest": ("govML", "templates/build/enforcement/artifact_integrity_manifest.json"),
    "managed-artifact-source-migrations": ("govML", "templates/build/enforcement/artifact_integrity_source_migrations.json"),
    "managed-artifact-source-migrations-prior": ("govML", "templates/build/enforcement/artifact_integrity_source_migrations.prior-v1.json"),
    "managed-construction-fixture-data-loaded": ("govML", "templates/build/enforcement/construction_completeness_fixtures/data_loaded_proxy.json"),
    "managed-construction-fixture-complete": ("govML", "templates/build/enforcement/construction_completeness_fixtures/genuine_complete.json"),
    "managed-construction-fixture-under-build": ("govML", "templates/build/enforcement/construction_completeness_fixtures/under_build.json"),
    "managed-construction-gate": ("govML", "templates/build/enforcement/construction_completeness_gate.py"),
    "managed-coverage-gate": ("govML", "templates/build/enforcement/coverage_completeness_gate.py"),
    "managed-construction-emitter": ("govML", "templates/build/enforcement/emit_construction_manifest.py"),
    "managed-external-attribution-receipt": ("govML", "templates/build/enforcement/external_attribution_receipt.py"),
    "managed-gate-coverage-diff": ("govML", "templates/build/enforcement/gate_coverage_diff.py"),
    "managed-gate-coverage-registry": ("govML", "templates/build/enforcement/gate_coverage_registry.json"),
    "managed-known-good-profile": ("govML", "templates/build/enforcement/known_good_mev_profile.json"),
    "managed-enforcement-inventory": ("govML", "templates/build/enforcement/managed_enforcement_inventory.py"),
    "managed-inventory-bootstrap": ("govML", "templates/build/enforcement/managed_inventory_bootstrap.py"),
    "managed-invocation-identity": ("govML", "templates/build/enforcement/invocation_identity.py"),
    "managed-warmup-index-recorder": ("govML", "templates/build/enforcement/record_warmup_index_read.py"),
    "managed-research-workflow": ("govML", "templates/build/enforcement/research_integrity.yml"),
    "managed-research-pre-commit": ("govML", "templates/build/enforcement/research_integrity_pre_commit.sh"),
    "managed-write-artifact-bridge": ("govML", "templates/build/enforcement/write_artifact_integrity_bridge.py"),
    "managed-write-authority": ("govML", "templates/build/enforcement/write_authority.py"),
    "managed-write-boundary-verdict": ("govML", "templates/build/enforcement/write_boundary_verdict_event.py"),
    "managed-write-claims-frontend": ("govML", "templates/build/enforcement/write_claims_frontend.py"),
    "managed-write-integrity-gate": ("govML", "templates/build/enforcement/write_integrity_gate.py"),
    "emitter-runtime-phase-gates": ("govML", "scripts/generators/gen_phase_gates.py"),
    "emitter-runtime-data-report-checker": ("govML", "scripts/generators/gen_data_report_checker.py"),
    "emitter-runtime-rubric-checker": ("govML", "scripts/generators/gen_rubric_checker.py"),
    "emitter-runtime-integrity-checker": ("govML", "scripts/generators/gen_integrity_checker.py"),
    "emitter-runtime-channel-voice-checker": ("govML", "scripts/generators/gen_channel_voice_check.py"),
    "newsletter-upgrade-workflow": ("newsletter", ".github/workflows/newsletter-upgrade-integrity.yml"),
    "newsletter-bootstrap-capability": ("newsletter", ".github/integrity/newsletter/bootstrap-capability.json"),
    "newsletter-bootstrap-validator": ("rexcoleman.dev", ".github/write-enforcement/validate_newsletter_upgrade.py"),
})

# Successor-only closed extension.  Generation 4's 244-member contract remains
# byte-for-byte auditable through EXPECTED_MEMBERS and independent_review.py.
# A capability-change freeze opts into this closed extension explicitly;
# the issuer/verifier select between the two exact sets from the manifest's
# presence of this named transition member, never by subset acceptance.
SUCCESSOR_ADDITIONAL_MEMBERS = {
    "ci-enforcement-materializer": (
        "govML",
        "templates/build/enforcement/ci_materialize_enforcement.py",
    ),
    "protected-downstream-bundle-secret-transition": (
        "rexcoleman.dev",
        ".github/write-enforcement/provision_downstream_bundle_secret.py",
    ),
}


def successor_members():
    value = dict(EXPECTED_MEMBERS)
    overlap = set(value) & set(SUCCESSOR_ADDITIONAL_MEMBERS)
    if overlap:
        raise ValueError("successor member id collision: %s" % sorted(overlap))
    value.update(SUCCESSOR_ADDITIONAL_MEMBERS)
    if len(set(value.values())) != len(value):
        raise ValueError("successor member subject collision")
    return value


def production_members_for_manifest(manifest, baseline=None):
    """Select the exact closed set for one known generation; never a subset."""
    rows = manifest.get("members") if isinstance(manifest, dict) else None
    observed = {
        row.get("member_id") for row in rows or []
        if isinstance(row, dict) and isinstance(row.get("member_id"), str)
    }
    base = EXPECTED_MEMBERS if baseline is None else baseline
    successor = dict(base)
    successor.update(SUCCESSOR_ADDITIONAL_MEMBERS)
    generation = manifest.get("authority_generation") if isinstance(manifest, dict) else None
    if generation is None and baseline is not None:
        # Unit-level byte/membership checks historically pass a reduced explicit
        # contract without the outer manifest loader. Production entrypoints
        # validate the generation before reaching this selector.
        return successor if observed & set(SUCCESSOR_ADDITIONAL_MEMBERS) else base
    if generation == HISTORICAL_AUTHORITY_GENERATION:
        if observed & set(SUCCESSOR_ADDITIONAL_MEMBERS):
            raise ValueError("generation-4 manifest contains successor members")
        return base
    if generation == AUTHORITY_GENERATION:
        return successor
    raise ValueError("manifest authority generation is not registered")

# Separate immutable authoring subjects may target the same installed runtime
# locus only when the frozen bytes are identical.  Keep distinct member IDs and
# distinct (repository, path) subjects; equality is checked by both builder and
# issuer before any authority is created.
EXACT_MEMBER_BYTE_ALIASES = (
    ("production-request-provisioner", "scaffold-hybrid-core-provisioning-prp"),
    ("atomic-consumer", "scaffold-hybrid-core-atomic-consumer"),
    ("route-runtime-mount", "scaffold-hybrid-core-runtime-mount"),
    ("production-package-init", "scaffold-hybrid-core-provisioning-package-init"),
    ("production-boundary", "scaffold-hybrid-core-provisioning-boundary"),
    ("production-fixed-adapter", "scaffold-hybrid-core-provisioning-fixed-adapter"),
    ("runner-adapter", "runner-adapter-launcher"),
    ("write-boundary-engine", "scaffold-hybrid-core-write-boundary-engine"),
    ("write-boundary-row-registry", "scaffold-hybrid-core-row-registry"),
    ("write-boundary-ledger-schema", "scaffold-hybrid-core-ledger-schema"),
    ("write-boundary-parent-admission-schema", "scaffold-hybrid-core-parent-admission-schema"),
    ("write-boundary-receipt-schema", "scaffold-hybrid-core-receipt-schema"),
    ("write-boundary-request-schema", "scaffold-hybrid-core-request-schema"),
    ("write-boundary-seam-registry", "scaffold-hybrid-core-seam-registry"),
    ("write-boundary-transform-registry", "scaffold-hybrid-core-transform-registry"),
    ("write-boundary-trusted-admission", "scaffold-hybrid-core-trusted-admission"),
)

# Closed authoring/runtime aliases for every signed member whose immutable
# authoring identity names a govML-installer-owned live target.  Source modes
# are Git tree modes.  The installed mode is the actual successor-installed
# live mode.  Runner adapter is the sole explicit source-to-live mode
# transform; every other row remains 100644 -> 0644.
MANAGED_LIVE_MEMBER_ALIASES = (
    ("atomic-consumer", "scaffold-hybrid-core-atomic-consumer", "write_integrity/consumer/atomic_consumer.py", "100644", "100644", 0o644),
    ("route-runtime-mount", "scaffold-hybrid-core-runtime-mount", "write_integrity/mounts/runtime_mount.py", "100644", "100644", 0o644),
    ("production-package-init", "scaffold-hybrid-core-provisioning-package-init", "write_integrity/provisioning/__init__.py", "100644", "100644", 0o644),
    ("production-boundary", "scaffold-hybrid-core-provisioning-boundary", "write_integrity/provisioning/boundary.py", "100644", "100644", 0o644),
    ("production-fixed-adapter", "scaffold-hybrid-core-provisioning-fixed-adapter", "write_integrity/provisioning/fixed_adapter.py", "100644", "100644", 0o644),
    ("runner-adapter", "runner-adapter-launcher", "write_integrity/runners/runner_adapter.py", "100755", "100644", 0o755),
    ("write-boundary-engine", "scaffold-hybrid-core-write-boundary-engine", "write_integrity/write_boundary/boundary_engine.py", "100644", "100644", 0o644),
    ("write-boundary-row-registry", "scaffold-hybrid-core-row-registry", "write_integrity/write_boundary/row_registry.json", "100644", "100644", 0o644),
    ("write-boundary-ledger-schema", "scaffold-hybrid-core-ledger-schema", "write_integrity/write_boundary/schemas/ledger.schema.json", "100644", "100644", 0o644),
    ("write-boundary-parent-admission-schema", "scaffold-hybrid-core-parent-admission-schema", "write_integrity/write_boundary/schemas/parent_admission.schema.json", "100644", "100644", 0o644),
    ("write-boundary-receipt-schema", "scaffold-hybrid-core-receipt-schema", "write_integrity/write_boundary/schemas/receipt.schema.json", "100644", "100644", 0o644),
    ("write-boundary-request-schema", "scaffold-hybrid-core-request-schema", "write_integrity/write_boundary/schemas/request.schema.json", "100644", "100644", 0o644),
    ("write-boundary-seam-registry", "scaffold-hybrid-core-seam-registry", "write_integrity/write_boundary/seam_registry.json", "100644", "100644", 0o644),
    ("write-boundary-transform-registry", "scaffold-hybrid-core-transform-registry", "write_integrity/write_boundary/transform_registry.json", "100644", "100644", 0o644),
    ("write-boundary-trusted-admission", "scaffold-hybrid-core-trusted-admission", "write_integrity/write_boundary/trusted_admission.py", "100644", "100644", 0o644),
)


def _literal_assignment(source: bytes, name: str):
    """Read one closed literal assignment without executing candidate code."""
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeError, SyntaxError) as exc:
        raise ValueError(f"managed inventory source invalid:{name}") from exc
    matches = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            value = node.value
            class FrozenSetNormalizer(ast.NodeTransformer):
                def visit_Call(self, call):  # noqa: N802 - ast visitor API
                    if (
                        isinstance(call.func, ast.Name)
                        and call.func.id == "frozenset"
                        and len(call.args) == 1
                        and not call.keywords
                    ):
                        return self.visit(call.args[0])
                    return self.generic_visit(call)

            value = FrozenSetNormalizer().visit(value)
            try:
                matches.append(ast.literal_eval(value))
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"managed inventory assignment nonliteral:{name}"
                ) from exc
    if len(matches) != 1:
        raise ValueError(f"managed inventory assignment population:{name}")
    return matches[0]


def derive_research_build_managed_contract(
    inventory_source: bytes, hybrid_manifest_source: bytes
) -> dict[str, tuple[str, str]]:
    """Derive the exact installer-owned research-build live population."""
    common = _literal_assignment(inventory_source, "COMMON")
    build_only = _literal_assignment(inventory_source, "BUILD_ONLY")
    profile_contract = _literal_assignment(inventory_source, "PROFILE_CONTRACT")
    signed_base = _literal_assignment(inventory_source, "SIGNED_BASE")
    emitter_closures = _literal_assignment(
        inventory_source, "EMITTER_RUNTIME_SURFACE_CLOSURES"
    )
    if not all(isinstance(value, dict) for value in (
        common, build_only, profile_contract, signed_base, emitter_closures
    )):
        raise ValueError("managed inventory literal shape")
    profile = profile_contract.get("research-build")
    if not isinstance(profile, dict) or set(profile) != {
        "research_type", "surfaces", "runner"
    }:
        raise ValueError("managed research-build profile shape")
    contract = dict(signed_base)
    for destination, source in {**common, **build_only}.items():
        contract[destination] = (
            "govML", f"templates/build/enforcement/{source}"
        )
    contract["scripts/run_gates.sh"] = (
        "govML", f"templates/build/enforcement/{profile['runner']}"
    )
    try:
        hybrid = json.loads(hybrid_manifest_source)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("hybrid install manifest invalid") from exc
    if not isinstance(hybrid, dict):
        raise ValueError("hybrid install manifest shape")
    contract["write_integrity/govml/hybrid_install_manifest.json"] = (
        "govML", "templates/build/enforcement/hybrid_install_manifest.json"
    )
    contract["scripts/hybrid_route_consumer.py"] = (
        "govML", "templates/build/enforcement/hybrid_route_consumer.py"
    )
    for row in hybrid.get("core_members", []):
        if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
            raise ValueError("hybrid core member shape")
        relative = row["path"]
        contract[relative] = (
            "govML", f"templates/build/enforcement/hybrid_core/{relative}"
        )
    for section in ("report_members", "row_complete_members"):
        for row in hybrid.get(section, []):
            if not isinstance(row, dict):
                raise ValueError(f"hybrid {section} member shape")
            destination = row.get("installed_path")
            source = row.get("source_path")
            if not isinstance(destination, str) or not isinstance(source, str):
                raise ValueError(f"hybrid {section} member path")
            contract[destination] = ("govML", source)
    emitter_names = set()
    for surface in profile["surfaces"]:
        closure = emitter_closures.get(surface)
        if not isinstance(closure, (set, frozenset)):
            raise ValueError("managed emitter closure shape")
        emitter_names.update(closure)
    for name in sorted(emitter_names):
        contract[f"scripts/publishing_emitters/{name}"] = (
            "govML", f"templates/build/enforcement/{name}"
        )
    if len(contract) != len(set(contract)):
        raise ValueError("duplicate managed destination")
    return contract


def validate_managed_live_member_aliases(
    loaded: dict[str, bytes],
    source_modes: dict[str, str],
    contract: dict[str, tuple[str, str]],
) -> None:
    """Close every authoring alias over the authenticated managed contract."""
    required_ids = {
        member_id
        for row in MANAGED_LIVE_MEMBER_ALIASES
        for member_id in row[:2]
    } | {
        "managed-enforcement-inventory", "scaffold-hybrid-install-manifest"
    }
    present = required_ids & set(contract)
    if not present:
        return
    if present != required_ids:
        raise ValueError("managed live alias contract incomplete")
    inventory = loaded.get("managed-enforcement-inventory")
    hybrid = loaded.get("scaffold-hybrid-install-manifest")
    if not isinstance(inventory, bytes) or not isinstance(hybrid, bytes):
        raise ValueError("managed alias source unavailable")
    managed = derive_research_build_managed_contract(inventory, hybrid)
    source_to_ids = {}
    for member_id, subject in contract.items():
        source_to_ids.setdefault(subject, []).append(member_id)
    table = MANAGED_LIVE_MEMBER_ALIASES
    if len(table) != 15:
        raise ValueError("managed live alias count")
    if len({row[0] for row in table}) != len(table):
        raise ValueError("managed live authoring id duplicate")
    if len({row[1] for row in table}) != len(table):
        raise ValueError("managed live runtime id duplicate")
    if len({row[2] for row in table}) != len(table):
        raise ValueError("managed live target duplicate")
    table_overlap = set()
    for (
        authoring_id, runtime_id, target, authoring_mode, runtime_mode,
        installed_mode,
    ) in table:
        if authoring_id not in contract or runtime_id not in contract:
            raise ValueError("managed live alias absent from contract")
        if contract[authoring_id] == contract[runtime_id]:
            raise ValueError("managed live aliases collapse onto one subject")
        if managed.get(target) != contract[runtime_id]:
            raise ValueError(f"managed live runtime target mismatch:{target}")
        if loaded.get(authoring_id) != loaded.get(runtime_id):
            raise ValueError(
                f"managed live alias divergence:{authoring_id}:{runtime_id}"
            )
        if source_modes.get(authoring_id) != authoring_mode:
            raise ValueError(f"managed live authoring mode:{authoring_id}")
        if source_modes.get(runtime_id) != runtime_mode:
            raise ValueError(f"managed live runtime mode:{runtime_id}")
        expected_installed_mode = 0o755 if target == (
            "write_integrity/runners/runner_adapter.py"
        ) else 0o644
        if installed_mode != expected_installed_mode:
            raise ValueError(f"managed live installed mode:{target}")
        authoring_subject = contract[authoring_id]
        if authoring_subject == ("research_enforcement_activation", target):
            table_overlap.add((authoring_id, runtime_id, target))
        elif not (
            authoring_subject[0] == "govML"
            and authoring_subject[1].startswith(
                "templates/build/enforcement/signed_authoring/"
            )
        ):
            raise ValueError(f"managed live authoring subject:{authoring_id}")
    actual_overlap = set()
    for authoring_id, (repository, path) in contract.items():
        if repository != "research_enforcement_activation" or path not in managed:
            continue
        runtime_ids = source_to_ids.get(managed[path], [])
        if len(runtime_ids) != 1:
            raise ValueError(f"managed live runtime identity population:{path}")
        actual_overlap.add((authoring_id, runtime_ids[0], path))
    if actual_overlap != table_overlap:
        raise ValueError(
            "managed live alias population mismatch:"
            f"missing={sorted(actual_overlap - table_overlap)}:"
            f"extra={sorted(table_overlap - actual_overlap)}"
        )

# The authoring generators below are not the installed comparison identity.
# Each publishing scaffold receives the vendored subject below at the listed
# destination. The installed subject remains signed; manifest construction
# reads the authoring subject at that same immutable govML commit and proves
# source-to-vendor byte equality before any installation is attempted.
EXPECTED_EMITTER_RUNTIME_INSTALLATIONS = {
    "scripts/publishing_emitters/blog_publish_mount.py": {
        "authoring": ("govML", "scripts/generators/blog_publish_mount.py"),
        "installed": ("govML", "templates/build/enforcement/blog_publish_mount.py"),
    },
    "scripts/publishing_emitters/blog_runtime_mount.py": {
        "authoring": ("govML", "scripts/generators/blog_runtime_mount.py"),
        "installed": ("govML", "templates/build/enforcement/blog_runtime_mount.py"),
    },
    "scripts/publishing_emitters/content_remediate.py": {
        "authoring": ("govML", "scripts/generators/content_remediate.py"),
        "installed": ("govML", "templates/build/enforcement/content_remediate.py"),
    },
    "scripts/publishing_emitters/gen_blog_post.py": {
        "authoring": ("govML", "scripts/generators/gen_blog_post.py"),
        "installed": ("govML", "templates/build/enforcement/gen_blog_post.py"),
    },
    "scripts/publishing_emitters/gen_channel_voice_check.py": {
        "authoring": ("govML", "scripts/generators/gen_channel_voice_check.py"),
        "installed": ("govML", "templates/build/enforcement/gen_channel_voice_check.py"),
    },
    "scripts/publishing_emitters/gen_data_report_checker.py": {
        "authoring": ("govML", "scripts/generators/gen_data_report_checker.py"),
        "installed": ("govML", "templates/build/enforcement/gen_data_report_checker.py"),
    },
    "scripts/publishing_emitters/gen_distribution_kit.py": {
        "authoring": ("govML", "scripts/generators/gen_distribution_kit.py"),
        "installed": ("govML", "templates/build/enforcement/gen_distribution_kit.py"),
    },
    "scripts/publishing_emitters/gen_experiment_learning.py": {
        "authoring": ("govML", "scripts/generators/gen_experiment_learning.py"),
        "installed": ("govML", "templates/build/enforcement/gen_experiment_learning.py"),
    },
    "scripts/publishing_emitters/gen_integrity_checker.py": {
        "authoring": ("govML", "scripts/generators/gen_integrity_checker.py"),
        "installed": ("govML", "templates/build/enforcement/gen_integrity_checker.py"),
    },
    "scripts/publishing_emitters/gen_manifest_verifier.py": {
        "authoring": ("govML", "scripts/generators/gen_manifest_verifier.py"),
        "installed": ("govML", "templates/build/enforcement/gen_manifest_verifier.py"),
    },
    "scripts/publishing_emitters/gen_market_signal.py": {
        "authoring": ("govML", "scripts/generators/gen_market_signal.py"),
        "installed": ("govML", "templates/build/enforcement/gen_market_signal.py"),
    },
    "scripts/publishing_emitters/gen_methodology_overview.py": {
        "authoring": ("govML", "scripts/generators/gen_methodology_overview.py"),
        "installed": ("govML", "templates/build/enforcement/gen_methodology_overview.py"),
    },
    "scripts/publishing_emitters/gen_newsletter_issue.py": {
        "authoring": ("govML", "scripts/generators/gen_newsletter_issue.py"),
        "installed": ("govML", "templates/build/enforcement/gen_newsletter_issue.py"),
    },
    "scripts/publishing_emitters/gen_paper_analysis.py": {
        "authoring": ("govML", "scripts/generators/gen_paper_analysis.py"),
        "installed": ("govML", "templates/build/enforcement/gen_paper_analysis.py"),
    },
    "scripts/publishing_emitters/gen_phase_gates.py": {
        "authoring": ("govML", "scripts/generators/gen_phase_gates.py"),
        "installed": ("govML", "templates/build/enforcement/gen_phase_gates.py"),
    },
    "scripts/publishing_emitters/gen_report_auditor.py": {
        "authoring": ("govML", "scripts/generators/gen_report_auditor.py"),
        "installed": ("govML", "templates/build/enforcement/gen_report_auditor.py"),
    },
    "scripts/publishing_emitters/gen_research_report.py": {
        "authoring": ("govML", "scripts/generators/gen_research_report.py"),
        "installed": ("govML", "templates/build/enforcement/gen_research_report.py"),
    },
    "scripts/publishing_emitters/gen_rubric_checker.py": {
        "authoring": ("govML", "scripts/generators/gen_rubric_checker.py"),
        "installed": ("govML", "templates/build/enforcement/gen_rubric_checker.py"),
    },
    "scripts/publishing_emitters/gen_sweep.py": {
        "authoring": ("govML", "scripts/generators/gen_sweep.py"),
        "installed": ("govML", "templates/build/enforcement/gen_sweep.py"),
    },
    "scripts/publishing_emitters/hybrid_publish_mount.py": {
        "authoring": ("govML", "scripts/generators/hybrid_publish_mount.py"),
        "installed": ("govML", "templates/build/enforcement/hybrid_publish_mount.py"),
    },
    "scripts/publishing_emitters/orchestrate.py": {
        "authoring": ("govML", "scripts/generators/orchestrate.py"),
        "installed": ("govML", "templates/build/enforcement/orchestrate.py"),
    },
}

EXPECTED_MEMBERS.update({
    "installed-emitter-runtime-blog-publish-mount": ("govML", "templates/build/enforcement/blog_publish_mount.py"),
    "installed-emitter-runtime-blog-runtime-mount": ("govML", "templates/build/enforcement/blog_runtime_mount.py"),
    "installed-emitter-runtime-content-remediate": ("govML", "templates/build/enforcement/content_remediate.py"),
    "installed-emitter-runtime-gen-blog-post": ("govML", "templates/build/enforcement/gen_blog_post.py"),
    "installed-emitter-runtime-gen-channel-voice-check": ("govML", "templates/build/enforcement/gen_channel_voice_check.py"),
    "installed-emitter-runtime-gen-data-report-checker": ("govML", "templates/build/enforcement/gen_data_report_checker.py"),
    "installed-emitter-runtime-gen-distribution-kit": ("govML", "templates/build/enforcement/gen_distribution_kit.py"),
    "installed-emitter-runtime-gen-experiment-learning": ("govML", "templates/build/enforcement/gen_experiment_learning.py"),
    "installed-emitter-runtime-gen-integrity-checker": ("govML", "templates/build/enforcement/gen_integrity_checker.py"),
    "installed-emitter-runtime-gen-manifest-verifier": ("govML", "templates/build/enforcement/gen_manifest_verifier.py"),
    "installed-emitter-runtime-gen-market-signal": ("govML", "templates/build/enforcement/gen_market_signal.py"),
    "installed-emitter-runtime-gen-methodology-overview": ("govML", "templates/build/enforcement/gen_methodology_overview.py"),
    "installed-emitter-runtime-gen-newsletter-issue": ("govML", "templates/build/enforcement/gen_newsletter_issue.py"),
    "installed-emitter-runtime-gen-paper-analysis": ("govML", "templates/build/enforcement/gen_paper_analysis.py"),
    "installed-emitter-runtime-gen-phase-gates": ("govML", "templates/build/enforcement/gen_phase_gates.py"),
    "installed-emitter-runtime-gen-report-auditor": ("govML", "templates/build/enforcement/gen_report_auditor.py"),
    "installed-emitter-runtime-gen-research-report": ("govML", "templates/build/enforcement/gen_research_report.py"),
    "installed-emitter-runtime-gen-rubric-checker": ("govML", "templates/build/enforcement/gen_rubric_checker.py"),
    "installed-emitter-runtime-gen-sweep": ("govML", "templates/build/enforcement/gen_sweep.py"),
    "installed-emitter-runtime-hybrid-publish-mount": ("govML", "templates/build/enforcement/hybrid_publish_mount.py"),
    "installed-emitter-runtime-orchestrate": ("govML", "templates/build/enforcement/orchestrate.py"),
})

EXPECTED_MEMBERS.update({
    "moon-agent-build-orchestrator": ("Moonshots_Career_Thesis_v2", ".claude/agents/build-orchestrator.md"),
    "moon-agent-build-runner": ("Moonshots_Career_Thesis_v2", ".claude/agents/build-runner.md"),
    "moon-agent-execution-orchestrator": ("Moonshots_Career_Thesis_v2", ".claude/agents/execution-orchestrator.md"),
    "moon-agent-implementation-coach": ("Moonshots_Career_Thesis_v2", ".claude/agents/implementation-coach.md"),
    "moon-agent-kernel-coach": ("Moonshots_Career_Thesis_v2", ".claude/agents/kernel-coach.md"),
    "moon-agent-research-executor": ("Moonshots_Career_Thesis_v2", ".claude/agents/research-executor.md"),
    "moon-agent-research-orchestrator": ("Moonshots_Career_Thesis_v2", ".claude/agents/research-orchestrator.md"),
    "moon-agent-research-planner": ("Moonshots_Career_Thesis_v2", ".claude/agents/research-researcher-planner.md"),
    "moon-agent-research-verifier": ("Moonshots_Career_Thesis_v2", ".claude/agents/research-verifier.md"),
    "moon-agent-spec-freshness": ("Moonshots_Career_Thesis_v2", "scripts/validate_agent_spec_freshness.py"),
    "moon-warmup-protocol": ("Moonshots_Career_Thesis_v2", ".claude/session/warmup.md"),
})

ROUTE_OWNED_MEMBER_IDS = {
    "route-runtime-mount", "installed-emitter-runtime-blog-runtime-mount",
    "installed-emitter-runtime-gen-research-report",
    "installed-emitter-runtime-gen-newsletter-issue",
    "installed-emitter-runtime-gen-blog-post",
    "installed-emitter-runtime-gen-paper-analysis",
    "installed-emitter-runtime-gen-methodology-overview",
    "installed-emitter-runtime-gen-experiment-learning",
    "installed-emitter-runtime-gen-market-signal",
    "installed-emitter-runtime-content-remediate",
    "installed-emitter-runtime-blog-publish-mount",
    "installed-emitter-runtime-gen-distribution-kit", "route-distribution-wrapper",
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


STAGED_NONPRODUCTION_MANIFEST_SCHEMA = (
    "rea.write.enforcement-bundle-manifest.staged-nonproduction.v1"
)
STAGED_NONPRODUCTION_WEA_SCHEMA = "rea.write.wea.staged-nonproduction.v1"
STAGED_NONPRODUCTION_PURPOSE = "STAGED_NONPRODUCTION_CONVERGENCE_PROOF"
STAGED_NONPRODUCTION_RECEIPT_SCHEMA = (
    "rea.write.remote-issuance-receipt.staged-nonproduction.v1"
)
STAGED_NONPRODUCTION_HYBRID_SCHEMA = (
    "rea.write.hybrid-capability-authority.staged-nonproduction.v1"
)
STAGED_NONPRODUCTION_HYBRID_PURPOSE = (
    "VERIFY_ONLY_STAGED_NONPRODUCTION_REGISTRY"
)
STAGED_NONPRODUCTION_ADDITIONAL_MEMBERS = {
    "staged-nonproduction-trusted-public-key": (
        "govML",
        "tests/fixtures/s132_staged_nonproduction_ed25519_public.pem",
    ),
}


def staged_nonproduction_members():
    """Return the frozen staging contract without production trust roots.

    Staging is an explicit 245-member superset with one dedicated committed
    fixture key.  The production 244-member contract and both production
    trust roots remain present and unchanged.
    """
    members = dict(EXPECTED_MEMBERS)
    members.update(STAGED_NONPRODUCTION_ADDITIONAL_MEMBERS)
    return members


def group_member_contract(contract):
    grouped = {}
    for member_id, (repository, path) in contract.items():
        grouped.setdefault(repository, []).append((member_id, path))
    return {repository: tuple(rows) for repository, rows in grouped.items()}

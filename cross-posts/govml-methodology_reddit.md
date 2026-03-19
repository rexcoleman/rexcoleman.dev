# How I Govern AI-Assisted ML Projects (Open Source Framework)

After 4 ML projects at Georgia Tech, I'd run 14 manual audit cycles with 30+ findings each. The governance wasn't the problem — the manual enforcement was. So I built govML: governance-as-code for ML research.

**The architecture has three layers:**

Layer 1 (Templates): 42 templates defining what must be true — data contracts, experiment protocols, phase gates. DATA_MANIFEST forces you to declare every dataset's hash, source URL, and license before training. EXPERIMENT_PROTOCOL requires hypothesis, variables, and success criteria before running a single experiment.

Layer 2 (Generators): 19 executable scripts that enforce governance automatically. gen_sweep.py orchestrates hyperparameter sweeps with mandatory seed logging. gen_manifest_check.py verifies every file matches its declared hash. When I added automated audit generators G13-G16 (report consistency, data-report alignment, rubric tracing, integrity checks), manual audit cycles dropped from 14 to zero.

Layer 3 (Orchestration): MCP-based agent orchestrator that reads governance templates, checks phase gate status, and proposes the next action. Human approves or rejects at each decision point.

**What I learned:**

Governance docs that aren't executable are decoration. The generators are what prevent errors, not the templates. The highest-leverage template was the last one built — PUBLICATION_PIPELINE, governing the blog workflow. govML governed everything except publishing for months. PROJECT_BRIEF (thesis-first thinking) changed project starts: one project went from mkdir to complete FINDINGS.md in a single session.

4 quickstart profiles (minimal to contract-track). Tested across 9 projects with 469+ tests. Each project compounded on the last: Gen 0 had ~15 manual steps, Gen 4 takes <5 minutes setup.

Full write-up with code: https://rexcoleman.dev/posts/govml-methodology/

Repo: https://github.com/rexcoleman/govML

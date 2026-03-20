---
title: "How I Govern AI-Assisted ML Projects"
date: 2026-03-14
description: "I built a governance framework for ML projects after watching 14 manual audit cycles nearly break my workflow. Here's how govML works and why governance-as-code is the only way to scale ML research."
tags: ["ml-governance", "build-in-public", "machine-learning", "govml"]
categories: ["ML Governance", "Builder Journal"]
format: "technical-blog"
audience_side: "both"
image_count: 1
author: "Rex Coleman"
ShowToc: true
TocOpen: false
cover:
  image: /images/og-govml-methodology.png
  alt: "How I Govern AI-Assisted ML Projects"
  hidden: true
images:
  - /images/og-govml-methodology.png
---

After four ML projects at Georgia Tech, I'd run 14 manual audit cycles with 30+ findings each. The governance wasn't the problem — the manual enforcement was. So I built govML.

## The Problem

Every ML project needs governance: reproducible experiments, documented decisions, data integrity checks, fair comparisons. But enforcing governance manually is a workflow killer. My unsupervised learning project had 7 audit cycles with 49+ findings. The RL project had 14 cycles with 30+ findings. I was spending more time auditing than experimenting.

The root cause: governance was prose in a document, not executable infrastructure. Contracts told me what to do but didn't do it for me.

To make this concrete: in my first three projects, I accumulated 36 commits and 7 audit cycles fixing issues that templates would have prevented — missing data manifests, undocumented hyperparameter choices, experiments that couldn't be reproduced because the random seed wasn't logged. Every audit cycle was a full re-read of the codebase against a checklist I was carrying in my head. That's not a governance problem. That's an automation problem.

## What I Built

**govML** is a governance framework for ML projects — 50+ templates, 10 profiles, 20+ generators, and an agent orchestrator prototype.

The architecture has three layers, each solving a different failure mode:

```
Layer 1: GOVERNANCE (templates)
  Defines WHAT must be true — data contracts, experiment protocols, phase gates
    ↓ generates
Layer 2: SCAFFOLDING (generators)
  Scripts that ENFORCE governance automatically — sweep orchestration,
  manifest verification, phase gate checks
    ↓ orchestrated by
Layer 3: ORCHESTRATION (agent)
  AI-driven workflow that manages the experiment lifecycle with human
  approval at decision points
```

**Layer 1** solves the "what did I forget?" problem. Templates like `DATA_MANIFEST` force you to declare every dataset's hash, source URL, and license before training. `EXPERIMENT_PROTOCOL` requires you to specify your hypothesis, independent/dependent variables, and success criteria before running a single experiment. You can't skip what you don't know you need — the template surfaces it.

**Layer 2** solves the "I know the rule but didn't check" problem. Generators are executable scripts that verify governance automatically. `gen_sweep.py` orchestrates hyperparameter sweeps with mandatory seed logging. `gen_manifest_check.py` verifies that every file referenced in the data manifest actually exists and matches its declared hash. When I added audit generators G13-G16 (report consistency, data-report alignment, rubric tracing, integrity checks), the manual audit cycles dropped from 14 to zero — not because the rules changed, but because enforcement became automatic.

**Layer 3** solves the "who drives the workflow?" problem. The agent orchestrator (MCP-based, running through Claude Code) reads the project's governance templates, checks phase gate status, and proposes the next action. The human approves or rejects at each decision point. The agent handles the tedious sequencing — "run the sweep, verify the manifest, update the decision log, check the phase gate" — while the researcher retains judgment over what to investigate next.

![govML agent boundary architecture — three-layer design separating governance templates, enforcement generators, and AI orchestration](/images/posts/govml-methodology/agent_boundary.png)

### How It Works in Practice

Initialize a new project:

```bash
bash scripts/init_project.sh /path/to/project --profile security-ml --fill
```

This copies 21 governance templates, pre-fills common placeholders from `project.yaml`, and gives you a PROJECT_BRIEF to fill before writing any code. The brief forces you to define your thesis, research questions, scope, and publication target upfront.

Every experiment runs through phase gates. You can't advance to the next phase until the current gate passes. Decisions are logged in ADR format at every gate — mandatory, not optional. When the experiments are done, a PUBLICATION_PIPELINE template governs the blog post from draft structure through distribution checklist.

### The Automation Progression

Each project compounded on the last:

| Generation | Project | Manual Steps |
|------------|---------|-------------|
| Gen 0 | Supervised Learning | ~15 steps |
| Gen 1 | Optimization | ~12 steps |
| Gen 2 | Unsupervised | ~10 steps |
| Gen 3 | Reinforcement Learning | ~6 steps |
| Gen 4 | Adversarial IDS (with govML v2.4) | <5 minutes setup |

The key accelerators: `--fill` for bulk placeholder substitution, `PROJECT_BRIEF` for thesis-first thinking, and `PUBLICATION_PIPELINE` for governing the highest-leverage activity — publishing.

## What I Learned

**Governance docs that aren't executable are decoration.** The templates matter, but the generators (sweep orchestration, manifest verification, phase gates) are what actually prevent errors. When I added automated audit generators (G13-G16), manual audit cycles dropped from 14 to zero.

**The highest-leverage template was the one I built last.** PUBLICATION_PIPELINE governs the blog workflow — the single most important brand activity. govML governed everything except publishing for months. The irony of a governance framework that doesn't govern its own distribution was the key insight that led to v2.4.

**PROJECT_BRIEF changes behavior, not just documentation.** When you force thesis + research questions + scope BEFORE code, projects start differently. My [vulnerability prioritization project](/posts/cvss-gets-it-wrong/) went from `mkdir` to complete FINDINGS.md in a single session — because the brief defined what I was proving before I wrote a line of Python.

## The Numbers

- 57 templates across 4 directories (core, management, report, publishing)
- 10 profiles (minimal → contract-track, plus venue-specific)
- 27 generators (sweep orchestration, manifest verification, phase gates, leakage tests, blog drafting, and more)
- Continuously improved through v2.7 — issues surface and resolve each project cycle
- Tested across 9 projects with 469+ tests (4 academic, 4 frontier research, 1 systems benchmark)

## Try It

govML governs every project in my research portfolio. The methodology is described above; the tooling is internal.

govML is used internally across all Singularity Cybersecurity research projects. Every template was extracted from real project friction, not designed speculatively.

### Limitations

govML has been validated by a single user across 9 projects. Team-scale adoption, cross-organization deployment, and integration with existing MLOps pipelines remain untested. The generator coverage (20+ generators) addresses the most common audit failure patterns but doesn't yet cover all edge cases. The MCP-based enforcement requires Claude Code — teams using other AI assistants need manual template application.

### What's Next

govML governed every project in my research portfolio. See it in action: [I Red-Teamed AI Agents](/posts/agent-redteam/) (govML-governed) · [CVSS Gets It Wrong](/posts/cvss-gets-it-wrong/) (govML-governed) · [Adversarial IDS](/posts/adversarial-ids/) (govML-governed). The agent orchestrator and community adoption are the next priorities.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

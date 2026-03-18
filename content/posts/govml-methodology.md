---
title: "How I Govern AI-Assisted ML Projects"
date: 2026-03-14
description: "I built an open-source governance framework for ML projects after watching 14 manual audit cycles nearly break my workflow. Here's how govML works and why governance-as-code is the only way to scale ML research."
tags: ["ml-governance", "build-in-public", "machine-learning", "govml"]
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

After four ML projects at Georgia Tech, I'd run 14 manual audit cycles with 30+ findings each. The governance wasn't the problem — the manual enforcement was. So I built [govML](https://github.com/rexcoleman/govML).

## The Problem

Every ML project needs governance: reproducible experiments, documented decisions, data integrity checks, fair comparisons. But enforcing governance manually is a workflow killer. My unsupervised learning project had 7 audit cycles with 49+ findings. The RL project had 14 cycles with 30+ findings. I was spending more time auditing than experimenting.

The root cause: governance was prose in a document, not executable infrastructure. Contracts told me what to do but didn't do it for me.

## What I Built

**govML** is an open-source governance framework for ML projects — 42 templates, 4 quickstart profiles, 19 generators, and an agent orchestrator prototype.

The architecture has three layers:

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

**PROJECT_BRIEF changes behavior, not just documentation.** When you force thesis + research questions + scope BEFORE code, projects start differently. My vulnerability prioritization project (FP-05) went from `mkdir` to complete FINDINGS.md in a single session — because the brief defined what I was proving before I wrote a line of Python.

## The Numbers

- 42 templates across 4 directories (core, management, report, publishing)
- 4 quickstart profiles (minimal → contract-track)
- 19 generators (sweep orchestration, manifest verification, phase gates, leakage tests, blog drafting, and more)
- Continuously improved through v2.7 — issues surface and resolve each project cycle
- Tested across 9 projects with 469+ tests (4 academic, 4 frontier research, 1 systems benchmark)

## Try It

govML is open source: [github.com/rexcoleman/govML](https://github.com/rexcoleman/govML)

```bash
git clone https://github.com/rexcoleman/govML.git
cd govML
bash scripts/init_project.sh /your/project --profile supervised --fill
```

If you run ML experiments and want reproducibility without the overhead, this is the framework I built to solve that problem for myself. Every template was extracted from real project friction, not designed speculatively.


---

*Rex Coleman is securing AI from the architecture up — building AI security systems across 4 ML paradigms, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

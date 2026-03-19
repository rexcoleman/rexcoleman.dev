---
title: "The same adversarial principle predicts robustness across 6 security domains"
date: 2026-03-19
draft: false
tags: ["adversarial-ml", "aca-methodology", "feature-controllability", "security-architecture"]
format: "til"
audience_side: "both"
---

**Adversarial Control Analysis (ACA) — the principle that system robustness depends on which features an attacker can manipulate — predicted security outcomes correctly across 6 different domains:** network intrusion detection, fraud detection, vulnerability prioritization, agent security, supply chain analysis, and post-quantum cryptography migration.

## Why this matters

Security teams typically treat each domain as its own silo with its own threat models, its own tools, and its own assessment frameworks. But the underlying adversarial dynamic is the same everywhere: an attacker controls some inputs, the defender controls others, and robustness depends on the ratio between them. ACA formalizes this into a repeatable methodology. When I applied the same feature controllability analysis across all six domains, the systems with the highest ratio of attacker-controlled features were consistently the least robust — regardless of model architecture, data modality, or deployment context.

## Source

This finding emerges from applying ACA across six frontier projects. The unified methodology is described in [Adversarial Control Analysis](/posts/adversarial-control-analysis/). Individual domain applications: [IDS](/posts/adversarial-ids/), [Agent Red-Team](/posts/agent-redteam/), [Vuln Prioritization](/posts/cvss-gets-it-wrong/), [RL Agents](/posts/rl-agent-vulnerability/), [Model Fingerprinting](/posts/model-fingerprinting/).

## What to do about it

1. **Before choosing a model, map which features the attacker controls.** This is a design-time decision that determines your security ceiling.
2. **Use the controllability ratio** (attacker-controlled features / total features) as an architectural risk metric. Systems above 50% need architectural redesign, not better models.
3. **Apply this cross-domain.** If you're only doing threat modeling within one domain, you're missing structural patterns that transfer.

One principle. Six domains. The same answer every time: know what the attacker controls before you build.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

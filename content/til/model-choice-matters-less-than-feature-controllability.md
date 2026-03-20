---
title: "Model choice matters less than feature controllability"
date: 2026-03-19
draft: false
tags: ["adversarial-ml", "feature-controllability", "machine-learning", "security-architecture"]
format: "til"
audience_side: "from-ai"
---

**Across adversarial ML experiments on network intrusion detection, the performance gap between the most and least robust models was less than 8%. The gap between high-controllability and low-controllability feature sets was over 40%.** Model selection is a rounding error compared to feature architecture.

## Why this matters

When teams build ML systems that face adversarial inputs — intrusion detection, fraud detection, spam filtering, malware classification — the default question is "which model is most robust?" That's the wrong first question. The right first question is "which features does the attacker control?"

If 70% of your input features can be manipulated by an adversary, no model architecture will save you. If only 20% are attacker-controlled, even a simple model holds up reasonably well. Feature controllability is a design-time architectural decision. Model choice is a training-time optimization decision. The architectural decision dominates.

## Source

This finding comes from the [Adversarial IDS](/posts/adversarial-ids/) research, where I trained multiple model architectures on the CICIDS2017 dataset and tested adversarial robustness under controlled feature manipulation budgets. The feature controllability analysis categorized every input feature by attacker accessibility. Full code: [github.com/rexcoleman/adversarial-ids-ml](https://github.com/rexcoleman/adversarial-ids-ml).

## What to do about it

1. **Map feature controllability before model selection.** For every feature in your system, ask: can an adversary directly manipulate this input?
2. **Minimize attacker-controlled features in your design.** If you can derive a feature from server-side data instead of client-supplied data, do it.
3. **Use controllability ratio as a risk metric.** Track (attacker-controlled features / total features) as a first-class system health indicator.

The model matters. The features matter 5x more.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

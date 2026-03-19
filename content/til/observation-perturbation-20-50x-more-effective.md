---
title: "Observation perturbation is 20-50x more effective than reward poisoning"
date: 2026-03-19
draft: false
tags: ["ai-security", "reinforcement-learning", "adversarial-ml", "rl-attacks"]
format: "til"
audience_side: "of-ai"
---

**In controlled experiments across two RL environments, observation perturbation attacks degraded agent performance 20-50x more than reward poisoning at equivalent attack budgets.** Modifying what the agent sees is dramatically more effective than corrupting its reward signal.

## Why this matters

Most RL security research focuses on reward hacking and reward poisoning — manipulating the training signal. That's important, but it's not where the real vulnerability is. Observation perturbation attacks (injecting noise or adversarial patterns into the agent's sensory input) are cheaper, faster, and harder to detect. They work at inference time, not just during training. And they require no access to the reward function.

This means the threat model for deployed RL agents is worse than commonly assumed. An attacker who can perturb observations — which is a realistic capability in many deployment contexts (sensor manipulation, API response injection, environment spoofing) — can degrade or redirect agent behavior without touching the training pipeline.

## Source

This finding comes from [FP-12 (RL Agent Vulnerability Analysis)](/posts/rl-agent-vulnerability/), where I tested 5 RL algorithms against 4 attack classes across 2 environments with matched attack budgets. Full code and results: [github.com/rexcoleman/rl-agent-vulnerability](https://github.com/rexcoleman/rl-agent-vulnerability).

## What to do about it

1. **Prioritize observation validation** in any deployed RL system. Input sanitization matters more than reward monitoring.
2. **Assume sensory inputs can be manipulated.** Design your agent architecture with adversarial observations as a first-class threat.
3. **Test observation perturbation attacks explicitly** during security evaluation. If your red-team only tests prompt injection, they're missing the bigger attack surface.

Prompt injection gets the headlines. Observation perturbation does the damage.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

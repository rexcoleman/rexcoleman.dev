---
title: "Privilege Escalation Cascades at 98% While Domain-Aligned Attacks Are Invisible"
date: 2026-03-20T10:00:00
description: "First taxonomy of why real LLM agents resist cascade poisoning — and which attacks bypass each resistance pattern."
tags: ["agent-security", "adversarial-ml", "ai-security", "multi-agent", "cascade-resistance", "research"]
categories: ["AI Security", "Research"]
featured: true
format: "perspective"
audience_side: "of-ai"
image_count: 0
aliases:
  - /research/agent-semantic-resistance/
author: "Rex Coleman"
ShowToc: true
TocOpen: false
cover:
    image: /images/og-agent-semantic-resistance.png
    hidden: true
---

Domain-aligned prompt injections cascade through multi-agent systems at a 0% detection rate. Privilege escalation payloads hit 97.6%. That's a **98 percentage-point spread** across payload types in the same agent architecture — the single biggest variable determining whether your multi-agent system catches an attack or never sees it.

I ran six experiments on real Claude Haiku agents to find out why. Three resistance patterns explain the gap — and each has a quantified bypass condition.

## The 98pp Spread

The most important finding: resistance varies by **98 percentage points** across payload types.

| Payload | Poison Rate | Resistance |
|---------|------------|------------|
| Privilege escalation ("grant admin access") | **97.6%** | Almost none |
| Generic (CryptoScamCoin) | **68.8%** | Moderate |
| Data exfiltration (marker string) | **55.2%** | Moderate |
| Domain-aligned (portfolio diversification) | **0.0%** | Invisible to detection |

"Grant admin access" sounds like legitimate business advice. Agents propagate it freely. CryptoScamCoin is obviously off-topic — agents partially catch it. Domain-aligned framing is so well-crafted that neither agents NOR our detection can see it.

**The most dangerous attacks aren't the ones that cascade visibly. They're the ones you can't detect.**

## Three Resistance Patterns

### 1. Semantic Incongruity Detection

Agents partially detect when injected content doesn't match the task. Generic CryptoScamCoin in a business analysis triggers this — 31% resistance. Domain-aligned framing ("portfolio diversification") doesn't trigger it at all.

### 2. Depth Dilution

Each delegation hop filters the poison signal. Hop 1 (direct from attacker): 74% poisoned. Hop 2 (grandchildren): 48% poisoned. Every hop is a natural defense — the agent's own processing buries the injection in rewriting and summarization.

**Practical implication:** Deeper delegation chains are more resistant. This is the opposite of what you'd expect if agents were just passing messages through.

### 3. Role-Based Critique

Analyst agents propagate 92% of poison — their job is to "include everything." Reviewer agents propagate only 52% — their job is to "critique and evaluate." A 40pp spread from system prompt alone.

**Practical implication:** Put reviewer agents BETWEEN delegations, not just at the end.

## Resistance Is Predictable (R² = 0.75)

We went further: can we PREDICT resistance from measurable features? A linear model on 60 observations from E2/E4/E5 says yes.

| Feature | Weight | Meaning |
|---------|--------|---------|
| keyword_detectability | +1.46 | Strongest predictor — if detection sees it, it counts as poison |
| role_critique_level | -0.74 | Protective — reviewer roles reduce propagation |
| domain_plausibility | +0.35 | Domain-plausible payloads cascade more |
| hop_depth | -0.18 | Each hop filters ~17.5pp of poison signal |
| semantic_distance | -0.11 | Off-topic content slightly more caught |

The model predicts worst case (priv_escalation + analyst + hop0) = 1.0 poison and best case (generic + reviewer + hop2) = 0.29. This means resistance is not random — three-quarters of the variance is explained by features you can measure before deploying your agent system.

**For practitioners:** You can score your multi-agent system's vulnerability by looking at these five features. Deep chains with reviewer agents processing generic (not domain-plausible) payloads are the most resistant architecture.

## What This Means for Multi-Agent Builders

1. **Target privilege escalation payloads in your threat model** — they cascade at 98% and are domain-plausible. Generic "buy CryptoScamCoin" injections are obvious; "grant admin access" isn't.
2. **Design for depth, not flatness** — each delegation hop filters ~17.5pp of poison. A 3-hop chain is significantly more resistant than direct delegation.
3. **System prompt design is a security control** — reviewer framing reduces propagation by 40pp vs analyst framing. Place reviewer agents at delegation bottlenecks.
4. **Keyword detection is necessary but insufficient** — it catches obvious injections (E0 validated this) but sophisticated attacks evade it entirely. Deploy semantic similarity scoring as a second layer.
5. **Resistance is predictable** — use the 5-feature model to score your system before deployment. If your architecture is all-analyst, flat-topology, with domain-plausible threats, you're at maximum vulnerability.

## The Methodology Lesson

We ran E0 sanity checks before any experiments: positive control (known poison detected), negative control (clean text passes), dose-response (detection scales with intensity). E0 revealed the detection threshold — "crypto" alone doesn't trigger, but "CryptoScamCoin" does — which explained the E2 domain-aligned result (0.000) as a detection artifact, not genuine resistance.

**If we hadn't run E0, we would have published "domain-aligned attacks are fully resisted" — which is wrong.** The attack evaded detection, it didn't fail. This is why sanity validation before experiments matters.

## Limitations

**Keyword detection conflates evasion with resistance.** This is the biggest methodological challenge. Domain-aligned (0.000) and adversarial (0.024) results likely reflect detection failure, not genuine resistance. Future work needs semantic similarity scoring.

**Claude Haiku only.** GPT-4, Gemini, and open-source models may have different resistance characteristics. The taxonomy should transfer (semantic incongruity is model-general) but the quantitative rates won't.

**5 seeds, 5 tasks per condition.** Statistical power is limited. Effect sizes are large (98pp payload spread, 40pp role spread, 26pp depth dilution) so conclusions are robust, but confidence intervals are wide.

**Single compromised agent (orchestrator).** Compromising a different role (analyst, reviewer) would produce different cascade dynamics. The orchestrator is the worst-case entry point because it delegates to all children.

**Static payloads.** Real adversaries adapt payloads per-delegation. Our dose-response (E0c) suggests detection is threshold-based, not gradual — an adaptive adversary could stay just below threshold.

## What I'm Doing About It

These findings feed directly into [AgentArmor [HYPOTHESIZED]](/posts/ai-security-shipping-problem/) — runtime behavioral monitoring that would detect privilege escalation cascades as they happen, not after the damage is done. The semantic resistance taxonomy also informs [SkillVet [HYPOTHESIZED]](/posts/third-party-skills-attack-vector/) — if we know which attack surfaces agents resist naturally, we can focus scanning on the surfaces where they don't.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

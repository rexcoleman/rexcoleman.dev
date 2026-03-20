---
title: "Why AI-Powered Attacks Need Architecture-Level Defense"
date: 2026-03-19
draft: false
tags: ["ai-security", "security-architecture", "adversarial-ml", "feature-controllability"]
categories: ["AI Security"]
format: "perspective"
audience_side: "from-ai"
image_count: 0
description: "Point solutions fail against AI-powered attacks because AI attacks adapt — the defense must be architectural."
author: "Rex Coleman"
ShowToc: true
TocOpen: true
---

**Thesis:** Point solutions — WAFs, signature-based antivirus, rule-based SIEMs — fail against AI-powered attacks because AI attacks adapt faster than signatures update. The defense must be architectural.

I've spent the last four months building and attacking ML-based security systems across six domains. The consistent finding is that the model you choose matters far less than the architecture you deploy it in. A well-architected defense with a mediocre model beats an unstructured defense with a state-of-the-art model. Every time.

## The Evidence

**1. Feature controllability predicts attack success better than model architecture.**

In my [adversarial IDS research](/posts/adversarial-ids/), I trained Random Forest, XGBoost, and Logistic Regression classifiers on CICIDS2017 (2.83M network flows, 78 features, 15 traffic classes). Then I attacked them. The finding: 57 of 78 features are attacker-controllable (packet timing, payload size, flow duration), while 14 are defender-observable only (TCP flags, destination port — set by the OS/network stack). When I designed attacks targeting only attacker-controllable features, all three models degraded. When I built defenses that weighted defender-observable features, all three models resisted. The model architecture was nearly irrelevant. The feature architecture determined robustness.

This is the core insight: signature-based defenses fail because they watch the features attackers control. Architecture-level defense means building around the features attackers can't touch.

**2. Observation perturbation is 20-50x more effective than reward poisoning on RL agents.**

In my [RL agent vulnerability research](/posts/rl-agent-vulnerability/), observation perturbation — corrupting what the agent sees — caused 40-49 point reward degradation even at minimal noise (epsilon=0.01). Reward poisoning — corrupting the training signal — produced only 0.2-1.6% policy divergence at up to 20% corruption. The ratio is 20-50x.

Why? Reward signals are aggregated over entire episodes. A corrupted reward at step 17 of a 100-step episode gets averaged out by 99 clean signals. The learning algorithm filters it. But an observation perturbation hits at decision time — the agent misreads its environment and acts on that misreading immediately. The wrong action cascades.

This is an architecture problem, not a model problem. No amount of model improvement fixes an observation pipeline that an attacker can intercept. The defense is architectural: authenticate observation channels, classify them by controllability, and build decision logic that weights trustworthy channels higher.

**3. Adversarial evasion defeats signature-based IDS because signatures are static and attacks are adaptive.**

Traditional IDS products maintain signature databases — known-bad patterns that trigger alerts. AI-powered attacks generate novel patterns that evade signatures by design. This isn't theoretical. The adversarial evasion rate against pattern-matching defenses approaches 100% when the attacker can iterate, because each iteration probes the signature space and adjusts. The defender updates signatures weekly. The attacker updates payloads per-request.

The architecture fix: stop relying on what the traffic looks like (signatures) and start relying on what the traffic does (behavioral analysis on defender-observable features). ML-for-defense is necessary, but only when deployed within an architecture that constrains what the ML needs to get right.

**4. 0% of prompt-injection defenses work against RL-specific attacks.**

My [agent red-teaming work](/posts/agent-redteam/) built 3 defense layers against prompt injection: input sanitization, tool permission boundaries, and output validation. These defenses reduced prompt injection success from 80% to measurably lower rates on several attack classes. Then I tested the same defenses against RL-specific attacks — reward poisoning, observation perturbation, policy extraction. The result: 0% effectiveness. Zero.

The attacks operate on completely different surfaces. Prompt defenses filter text. RL attacks corrupt numerical vectors, reward signals, and learned policies. A point solution designed for one attack surface provides zero protection against a different attack surface. Only an architectural approach — one that identifies all attack surfaces and builds layered defense across each — can cover the full threat model.

**5. The same principle works across six security domains.**

I've now applied [adversarial control analysis](/posts/adversarial-control-analysis/) — classify inputs by who controls them, then build defenses around the uncontrollable parts — across network IDS, vulnerability prediction, AI agent security, post-quantum cryptography, financial fraud detection, and software supply chain security. In every domain, the finding is structurally identical: the inputs the attacker can't touch are your real defense. The inputs they can touch are where your model will fail.

This cross-domain consistency is the strongest evidence that the principle is architectural, not domain-specific. It doesn't matter whether you're classifying network flows, predicting CVE exploitation, or monitoring agent behavior. The architecture determines which features the attacker can corrupt. The model determines how well you use the uncorrupted ones.

## What This Means for the Field

The AI security industry is investing heavily in better models — larger training sets, more sophisticated classifiers, adversarial training techniques. These investments have real value. But they're second-order improvements on a first-order problem: the architecture that the model sits inside.

A WAF with a perfect ML model is still a WAF. It sees traffic at one point in the request lifecycle, makes a binary decision, and has no visibility into what happens after. An architectural defense distributes detection across multiple points, weights features by controllability, and makes decisions based on what the attacker can't manipulate.

The industry mental model needs to shift from "which ML model should we buy?" to "which architecture ensures the ML model sees trustworthy inputs?"

## What I'm Doing About It

The methodology is called adversarial control analysis (ACA). The process is three steps: enumerate all inputs to the system, classify each input by who controls it (attacker, defender, system), and build defenses around the boundary. I've published the methodology, the code, and the findings across all six domains.

At [Singularity Cybersecurity](https://singularitycyber.com), every tool we build starts with a controllability classification. SkillVet [HYPOTHESIZED] classifies skill behaviors by whether they touch attacker-controllable surfaces. AgentArmor [HYPOTHESIZED] monitors the observation channels that controllability analysis flags as vulnerable. The architecture comes first. The ML comes second.

### Limitations

The 20-50x observation vs. reward poisoning ratio comes from tabular Q-Learning on small state spaces (5-dimensional). Deep RL on larger state spaces may show different ratios. The six-domain ACA results are from my own research, not independent replication. Feature controllability classification requires domain expertise and may not be automatable in all contexts. The "0% effectiveness" of prompt defenses against RL attacks reflects the specific defenses I built, not all possible prompt-level defenses.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

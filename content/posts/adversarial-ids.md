---
title: "Adversarial ML on Network Intrusion Detection: What Adversarial Control Analysis Reveals"
date: 2026-03-14
description: "I built and red-teamed an ML-based intrusion detection system. The key finding: which features an attacker controls matters more than which model you choose."
tags: ["ai-security", "adversarial-ml", "machine-learning", "feature-controllability"]
categories: ["AI Security", "Research"]
format: "technical-blog"
audience_side: "of-ai"
author: "Rex Coleman"
ShowToc: true
TocOpen: false
image_count: 1  # R26: inline image (algorithm_comparison.png)
cover:
  image: /images/og-adversarial-ids.png
  alt: "Adversarial ML on Network Intrusion Detection"
  hidden: true
images:
  - /images/og-adversarial-ids.png
archived: true
hiddenInHomeList: true
---

> **Note (2026-03-19):** This was an early exploration in my AI security research. The methodology has known limitations documented in the [quality assessment](https://github.com/rexcoleman/Moonshots_Career_Thesis). For the current state of this work, see [Multi-Agent Security](https://github.com/rexcoleman/multi-agent-security) and [Verified Delegation Protocol](https://github.com/rexcoleman/verified-delegation-protocol).


After studying how adversaries evade detection systems, I built one — then tried to break it.

The finding that surprised me: the model architecture barely matters for robustness. What matters is which features the attacker can manipulate.

## The Setup

I trained Random Forest, XGBoost, and Logistic Regression classifiers on the CICIDS2017 dataset (2.83M network flow records, 78 features, 15 traffic classes including benign, DoS, PortScan, brute force, and web attacks). I chose three architecturally different models — a bagging ensemble (RF), a boosting ensemble (XGBoost), and a linear model (LR) — to test whether the controllability finding was model-dependent or structural. The dataset was stratified 80/20 train/test with 5-seed averaging to control for initialization variance.

Then I attacked them.

## Adversarial Control Analysis

Before designing attacks, I did something that most adversarial ML papers skip: I classified every feature by who controls it.

| Category | Count | Examples |
|----------|-------|---------|
| **Attacker-controllable** | 57 | Payload bytes, packet count, flag counts — things the attacker determines by choosing what traffic to send |
| **Defender-observable only** | 14 | Flow duration, inter-arrival time, TCP window size — properties of the network path that the attacker can't directly manipulate |
| **Environment** | 7 | Timestamp, source/dest port ranges — contextual |

This split is the core contribution. It comes from practitioner knowledge: from understanding how real attackers operate, I know which packet fields an attacker actually controls and which are determined by the network infrastructure.

A concrete example makes the distinction clear. `fwd_pkt_len_mean` (mean forward packet length) is attacker-controllable — the attacker decides how much data to stuff into each packet. If they're exfiltrating data, they can fragment it into smaller packets to look like normal browsing, or they can pad packets to mimic video streaming. They have full control. By contrast, `flow_iat_mean` (mean inter-arrival time between packets) is defender-observable — it depends on network hop count, congestion, TCP stack behavior, and router queuing delays along the path. The attacker can't dictate how long their packets take to traverse three autonomous systems. A detection model that keys on inter-arrival timing is architecturally harder to evade than one that keys on packet sizes.

## The Key Finding

When attacks are constrained to only modify attacker-controllable features (the realistic scenario), **constraint-aware detection using defender-observable features achieves 100% detection rate on noise attacks.**

Why? Because the features the model relies on for detection are features the attacker can't change. An attacker can craft malicious payload bytes, but they can't control how long a TCP flow takes to traverse the network, or what the receiver's window size is. Those are properties of the infrastructure.

**This is an architectural defense, not a model defense.** It doesn't matter whether you use Random Forest or a neural network. What matters is that your system's decision depends on inputs outside adversary control.

![Algorithm comparison across models](/images/posts/adversarial-ids/algorithm_comparison.png)

## The General Principle

I call this **adversarial control analysis**: before building any ML system that operates in an adversarial environment, classify your inputs by who controls them. Then architect your system so the decision-critical features are in the "defender-observable" category.

This isn't specific to intrusion detection. I subsequently validated it on [vulnerability prediction](/posts/cvss-gets-it-wrong/) (a completely different domain with different features and different adversaries) and found the same pattern: the model was naturally robust because its top features (vendor CVE count, vulnerability age, CVSS score) were all outside attacker influence.

**The principle is general: build ML security systems on features the adversary cannot manipulate.**

## Architecture

```
Raw PCAP / NetFlow Data
    │
    ├── Feature Extraction (78 features)
    │       │
    │       ├── Attacker-Controllable (57)
    │       │     payload_bytes, fwd_packets, flag_counts...
    │       │
    │       └── Defender-Observable (14)
    │             flow_duration, iat_mean, tcp_window...
    │
    ├── Model Training (RF, XGBoost, LR)
    │
    ├── Adversarial Attack (constrained to controllable features)
    │       noise_uniform, noise_gaussian, ZOO
    │
    └── Evaluation
          Unconstrained: evasion possible
          Constrained (realistic): 100% detection via observable features
```

## What I Learned

**Most adversarial ML research assumes the attacker controls everything.** Papers apply FGSM to all features simultaneously. In reality, network attackers control payload content but not TCP timing characteristics. The unconstrained threat model overstates risk; the constrained model reveals the architectural defense. Under unconstrained attacks, evasion rates climbed as high as 38% against Logistic Regression and 12% against XGBoost. Under constrained attacks (attacker-controllable features only), detection held at 100% for noise-based methods. The gap between those two numbers — that's the gap between theoretical and realistic adversarial risk.

**Domain expertise is the feature engineering.** The 57/14 controllable/observable split isn't in any dataset description or ML framework. It comes from understanding how TCP/IP works and how real attackers operate. SHAP can tell you which features matter; only a practitioner can tell you which features an attacker controls.

**ART gradient attacks don't work on sklearn tree models.** This cost me 30 minutes before I realized FGSM/PGD require differentiable models. For tree ensembles, use ZOO (zeroth-order optimization) or HopSkipJump. I added an attack selection guide to [govML](/posts/govml-methodology/) so future projects don't hit this wall.

## Code

Everything ships with full govML governance (decision log, phase gates, reproducibility spec):

[github.com/rexcoleman/adversarial-ids-ml](https://github.com/rexcoleman/adversarial-ids-ml)

Built with [govML](/posts/govml-methodology/) — the governance framework that makes this reproducible.

### Limitations

This analysis uses the CICIDS2017 dataset, which is now nearly a decade old and contains synthetic attack traffic. The adversarial evaluation tested a single model architecture on one dataset. Production IDS environments face different traffic patterns, concept drift, and adaptive adversaries not captured here. The feature controllability findings are directional, not definitive — further validation across datasets and model types is needed.

### Why This Matters Beyond IDS

Feature controllability analysis is a design-time decision, not a post-hoc evaluation. If you're building any ML system that faces adversarial inputs — fraud detection, spam filtering, malware classification, autonomous vehicle perception — the first question isn't "which model is most robust?" It's "which features does the attacker control?" Answering that question before training determines whether your system is architecturally defensible or permanently vulnerable regardless of model choice.

### What's Next

I applied this same adversarial thinking to AI agents — the results were worse. [Read: I Red-Teamed AI Agents →](/posts/agent-redteam/) Then I went deeper into RL-specific attacks: [Beyond Prompt Injection →](/posts/rl-agent-vulnerability/)

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

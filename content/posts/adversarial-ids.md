---
title: "Adversarial ML on Network Intrusion Detection: What Adversarial Control Analysis Reveals"
date: 2026-03-14
description: "I built and red-teamed an ML-based intrusion detection system. The key finding: which features an attacker controls matters more than which model you choose."
tags: ["ai-security", "adversarial-ml", "machine-learning", "feature-controllability"]
author: "Rex Coleman"
ShowToc: true
TocOpen: false
cover:
  image: /images/og-adversarial-ids.png
  alt: "Adversarial ML on Network Intrusion Detection"
  hidden: true
images:
  - /images/og-adversarial-ids.png
---

After 15 years at Mandiant watching network intrusion detection systems fail against real adversaries, I built one — then tried to break it.

The finding that surprised me: the model architecture barely matters for robustness. What matters is which features the attacker can manipulate.

## The Setup

I trained Random Forest, XGBoost, and Logistic Regression classifiers on the CICIDS2017 dataset (2.83M network flow records, 78 features, 15 traffic classes). Standard ML-on-IDS — nothing novel yet.

Then I attacked them.

## Adversarial Control Analysis

Before designing attacks, I did something that most adversarial ML papers skip: I classified every feature by who controls it.

| Category | Count | Examples |
|----------|-------|---------|
| **Attacker-controllable** | 57 | Payload bytes, packet count, flag counts — things the attacker determines by choosing what traffic to send |
| **Defender-observable only** | 14 | Flow duration, inter-arrival time, TCP window size — properties of the network path that the attacker can't directly manipulate |
| **Environment** | 7 | Timestamp, source/dest port ranges — contextual |

This split is the core contribution. It comes from practitioner knowledge: after watching real network attacks for 15 years, I know which packet fields an attacker actually controls and which are determined by the network infrastructure.

## The Key Finding

When attacks are constrained to only modify attacker-controllable features (the realistic scenario), **constraint-aware detection using defender-observable features achieves 100% detection rate on noise attacks.**

Why? Because the features the model relies on for detection are features the attacker can't change. An attacker can craft malicious payload bytes, but they can't control how long a TCP flow takes to traverse the network, or what the receiver's window size is. Those are properties of the infrastructure.

**This is an architectural defense, not a model defense.** It doesn't matter whether you use Random Forest or a neural network. What matters is that your system's decision depends on inputs outside adversary control.

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

**Most adversarial ML research assumes the attacker controls everything.** Papers apply FGSM to all features simultaneously. In reality, network attackers control payload content but not TCP timing characteristics. The unconstrained threat model overstates risk; the constrained model reveals the architectural defense.

**Domain expertise is the feature engineering.** The 57/14 controllable/observable split isn't in any dataset description or ML framework. It comes from understanding how TCP/IP works and how real attackers operate. SHAP can tell you which features matter; only a practitioner can tell you which features an attacker controls.

**ART gradient attacks don't work on sklearn tree models.** This cost me 30 minutes before I realized FGSM/PGD require differentiable models. For tree ensembles, use ZOO (zeroth-order optimization) or HopSkipJump. I added an attack selection guide to [govML](https://github.com/rexcoleman/govML) so future projects don't hit this wall.

## Code

Everything is open source with full govML governance (decision log, phase gates, reproducibility spec):

[github.com/rexcoleman/adversarial-ids-ml](https://github.com/rexcoleman/adversarial-ids-ml)

Built with [govML](https://github.com/rexcoleman/govML) — the governance framework that makes this reproducible.


---

*Rex Coleman builds what's missing between ML research and production security. 9 open-source projects across 4 ML paradigms. MSCS Georgia Tech (ML). CFA. CISSP. Creator of [govML](https://github.com/rexcoleman/govML). [rexcoleman.dev](https://rexcoleman.dev)*

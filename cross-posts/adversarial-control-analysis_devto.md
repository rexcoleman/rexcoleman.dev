---
title: "One Principle, Six Domains: Adversarial Control Analysis for AI Security"
published: true
canonical_url: "https://rexcoleman.dev/posts/adversarial-control-analysis/"
tags: [aisecurity, methodology, adversarialml, securityarchitecture]
---

I started with one question: if a network attacker can only control some features of network traffic, shouldn't our IDS defenses focus on the features they *can't* control?

That question became a methodology. I called it adversarial control analysis (ACA) — classify every input by who controls it, then build defenses around the uncontrollable parts. It worked on intrusion detection. So I tried it on vulnerability prediction. Same result. Then AI agents. Then cryptography. Then financial fraud. Then software supply chains.

Six domains. Same principle. Every time, the finding is the same: **the inputs the attacker can't touch are your real defense.**

## The Methodology

ACA has three steps:

1. **Enumerate all inputs** to the system (features, parameters, data sources)
2. **Classify each input** by controller: attacker-controlled, defender-observable, system-determined
3. **Build defenses** around the boundary: monitor what the attacker can't control, restrict what they can

This is simple. What surprised me is how consistently it produces actionable insights across very different security domains.

## Six Domains, One Pattern

### 1. Network Intrusion Detection ([full post](/posts/adversarial-ids/))

The 78 features in CICIDS2017 divide into two categories:
- **57 attacker-controllable** (packet timing, payload size, flow duration)
- **14 defender-observable only** (TCP flags, destination port — set by OS/network stack)

When adversarial perturbations are restricted to only attacker-controllable features, attack success drops 35% for XGBoost (against noise perturbation). The most effective defense: monitor the features attackers can't forge.

### 2. Vulnerability Prediction ([full post](/posts/cvss-gets-it-wrong/))

ML crushes CVSS for predicting exploit likelihood (+24pp AUC). The top SHAP feature is EPSS percentile — a real-time threat intelligence signal that attackers can't manipulate (it's computed by FIRST.org from global telemetry). Static metadata that attackers influence (CVE descriptions, vendor-reported CVSS) is less predictive than dynamic signals they can't control.

### 3. AI Agent Security ([full post](/posts/agent-redteam/))

Attack success correlates inversely with defender observability. The reasoning chain — internal to the agent's processing loop — has 100% attack success because defenders can't see it. User prompts (visible, filterable) have 80%. Tool outputs (partially observable) have 25%. **The less you can observe, the more vulnerable you are.**

### 4. Post-Quantum Cryptography

70% of quantum-vulnerable crypto in your codebase lives in libraries you depend on — you can't fix it directly. Classical exploit risk (attacker-controllable: exploit complexity, network access requirements) matters more than quantum risk (attacker-controllable only with future quantum computers) for prioritizing migration today.

### 5. Financial Fraud Detection

On synthetic PaySim data, system-controlled features alone achieve 81% of full model performance — the adversary-resistant detection floor. CFA-informed features (amount-to-median ratios, merchant risk tiers) capture 91% of what the full model captures. Domain expertise encoded as features targeting what fraudsters can't control (card verification systems, merchant risk scores) is more robust than features targeting what they can (transaction amounts, timing).

### 6. AI Supply Chain Security

The biggest risk isn't in what attackers inject — it's in what developers trust. `pickle.load` gives arbitrary code execution. 75% of critical findings are developer-fixable. The controllability insight: defenders control the deserialization pipeline (which formats to accept, which loaders to use), even though attackers control the model files.

## Why It Works

ACA works because security is fundamentally about **asymmetric control**. Attackers control some inputs. Defenders observe others. The system determines the rest. The boundary between these categories is where security architecture lives.

Most ML security research treats all features equally perturbable. Most security frameworks focus on the attack surface without mapping the control surface. ACA bridges both: it uses the control map to focus defenses where they'll survive adversarial pressure.

## What I'm Doing About It

I'm extending ACA to three new ML paradigms:

- **Reinforcement Learning (FP-12):** Agents have a new control surface — reward signals and observations. Which are attacker-controllable? Which are system-determined?
- **Unsupervised Learning (FP-13):** For model behavioral fingerprinting, the defender controls the reference inputs (the probe). The attacker controls the model weights. ACA predicts which backdoor types are hardest to detect.
- **Optimization (FP-14):** In adversarial training, the defender controls the optimizer and schedule. The attacker controls the adversarial examples. ACA maps the defense surface.

Same principle. Four paradigms. Every level of the AI stack.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

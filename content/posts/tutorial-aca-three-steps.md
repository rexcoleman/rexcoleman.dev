---
title: "Apply Adversarial Control Analysis to Your ML System in 3 Steps"
date: 2026-03-19
draft: false
tags: ["tutorial", "adversarial-ml", "security-architecture", "methodology", "aca"]
format: "tutorial"
audience_side: "both"
image_count: 0  # R26: text diagram present (ASCII architecture diagram)
description: "Classify every input to your ML system by who controls it, then architect your defenses around the features adversaries cannot touch."
archived: true
---

> **Note (2026-03-19):** This was an early exploration in my AI security research. The methodology has known limitations documented in the [quality assessment](https://github.com/rexcoleman/Moonshots_Career_Thesis). For the current state of this work, see [Multi-Agent Security](https://github.com/rexcoleman/multi-agent-security) and [Verified Delegation Protocol](https://github.com/rexcoleman/verified-delegation-protocol).


## Problem Statement

You have deployed an ML model and someone asks: "Is it robust to adversarial attack?" You do not have a principled way to answer. You could fuzz every input, but that is expensive and tells you nothing about which attacks are structurally impossible versus which are just untested. You need a method that maps the attack surface before you start testing.

Adversarial Control Analysis (ACA) gives you that map. It is a three-step process that classifies every input by who controls it, then focuses your defenses on the inputs the adversary cannot manipulate. I have applied it across six domains -- network IDS, vulnerability management, AI agents, post-quantum crypto, fraud detection, and ML supply chains -- and the finding is always the same: the inputs the attacker cannot touch are your real defense.

```
Step 1: ENUMERATE          Step 2: CLASSIFY           Step 3: ARCHITECT
┌─────────────────┐     ┌─────────────────────┐    ┌──────────────────┐
│ List all input  │     │ Who controls each?  │    │ Design around    │
│ features your   │────→│                     │───→│ defender-         │
│ model uses      │     │ Attacker│Defender│Sys│    │ observable       │
└─────────────────┘     └─────────────────────┘    │ features         │
                                                    └──────────────────┘
```

## Prerequisites

- An ML system with a defined feature set (even on paper)
- Understanding of your system's threat model (who is the adversary, what do they want)
- 30-60 minutes of focused analysis time
- No code required for the analysis itself

## Step 1: List All Input Features Your Model Uses

Start with a complete inventory. Every feature, every data source, every preprocessing step that feeds into your model is an input. Do not skip anything -- the features you forget about are often the ones attackers target.

For each feature, record:

```
Feature Name | Data Source | Type (numeric/categorical/text/binary)
```

Here is an example from a vulnerability prioritization model (FP-05):

```
Feature               | Source        | Type
---                   | ---           | ---
cvss_score            | NVD API       | numeric
epss_percentile       | FIRST.org     | numeric
has_exploit_ref       | NVD refs      | binary
vendor_cve_count      | NVD derived   | numeric
desc_length           | NVD desc      | numeric
kw_sql_injection      | NVD desc      | binary
kw_remote_code_exec   | NVD desc      | binary
cwe_CWE-79            | NVD CWE       | binary
pub_year              | NVD metadata  | numeric
cve_age_days          | NVD derived   | numeric
has_patch_ref         | NVD refs      | binary
```

Be exhaustive. In the FP-05 project, the model used 49 features across 8 feature groups. Missing even one group would have left a blind spot in the controllability analysis.

## Step 2: Classify Each Feature by Who Controls It

For every feature, ask: can the adversary change this value in a way that would influence the model's output?

There are three categories:

**Attacker-controlled:** The adversary can directly set or manipulate this value. Examples: CVE description text (attacker can submit misleading descriptions), packet payload bytes (attacker chooses what to send), user prompts to an AI agent.

**Defender-observable:** The adversary cannot change this value, but the defender can observe it. Examples: EPSS percentile (computed by FIRST.org from global telemetry), vendor CVE history (derived from the full NVD corpus), TCP flags (set by the OS network stack).

**System-determined:** Neither party controls this; it is determined by the system or environment. Examples: model architecture, inference pipeline configuration, publication timestamp.

Apply the classification:

```
Feature               | Controller          | Can Attacker Change?
---                   | ---                 | ---
cvss_score            | Defender-observable | No (assigned by NVD analysts)
epss_percentile       | Defender-observable | No (computed from global telemetry)
has_exploit_ref       | Defender-observable | No (NVD analysts add exploit refs)
vendor_cve_count      | Defender-observable | No (historical record)
desc_length           | Attacker-controlled | Yes (attacker writes the disclosure)
kw_sql_injection      | Attacker-controlled | Yes (derived from description text)
kw_remote_code_exec   | Attacker-controlled | Yes (derived from description text)
cwe_CWE-79            | Defender-observable | No (assigned by NVD analysts)
pub_year              | System-determined   | No (set by NVD)
cve_age_days          | System-determined   | No (derived from publication date)
has_patch_ref         | Defender-observable | No (patch links added by vendors)
```

Count the totals. In FP-05, the split was 15 attacker-controllable features (mostly text-derived) and 11 defender-observable features. The attacker controls 58% of features by count. That sounds alarming -- until you look at which features actually drive predictions.

## Step 3: Architect Around Defender-Observable Features

Now cross-reference your controllability map with your model's feature importance. The question is: do the features the attacker controls actually matter?

In FP-05, SHAP analysis revealed:

- **EPSS percentile** (defender-observable) = mean |SHAP| of 1.096 (highest)
- **has_exploit_ref** (defender-observable) = 0.573
- **cvss_score** (defender-observable) = 0.430
- **vendor_cve_count** (defender-observable) = 0.429
- **desc_length** (attacker-controlled) = 0.367
- **kw_sql_injection** (attacker-controlled) = 0.230

The top four features are all defender-observable. The model's decision boundary depends primarily on inputs the attacker cannot manipulate. This is not an accident -- it is the architectural defense.

Ablation confirmed it quantitatively: removing all attacker-controlled text features improved XGBoost AUC by +2.4pp. The text features were adding noise, not signal. A production deployment could drop them entirely and get a more robust model.

**The design rule:** If your model relies heavily on attacker-controlled features, you have two options:

1. **Constrain the model.** Drop or down-weight attacker-controlled features. In FP-05, removing description stats and keywords improved performance.

2. **Add defender-observable features.** Find signals the attacker cannot manipulate. In network IDS (FP-01), defender-observable features like TCP flags and destination ports reduced adversarial attack success by 35%.

3. **Monitor the boundary.** If you must use attacker-controlled features, monitor them for anomalous distributions. Sudden shifts in description text patterns could indicate manipulation attempts.

## Worked Example: AI Agent Input Surfaces

ACA scales beyond tabular ML. In the AI agent red-teaming project (FP-02), the "features" are the input surfaces to an autonomous agent:

```
Input Surface         | Controller            | Attack Success Rate
---                   | ---                   | ---
User prompt           | Attacker-controlled   | 80%
Tool parameters       | Attacker-controlled   | 75%
Conversation history  | Poisonable            | 67%
Tool outputs          | Partially controllable| 25%
Reasoning chain       | Partially controllable| 100%
```

The pattern holds: attack success correlates inversely with defender observability. The reasoning chain -- internal to the agent, invisible to the defender -- has 100% attack success. User prompts, which are visible and filterable, sit at 80%. Tool outputs, which are partially observable through logging, drop to 25%.

The architectural response: make the unobservable observable. Log reasoning chains. Validate multi-step plans before execution. Add a semantic filter (LLM-as-judge) for inputs that pattern matching cannot catch.

## Verification

Your ACA is working if:

1. **Every feature is classified.** No gaps. If you are unsure about a feature, default to attacker-controlled (conservative).
2. **You can quantify the split.** "15 attacker-controlled, 11 defender-observable" is actionable. "Some features might be manipulable" is not.
3. **Feature importance aligns with controllability.** If your top features are defender-observable, your model is architecturally robust. If your top features are attacker-controlled, you have work to do.
4. **You can draw the defense boundary.** Which features do you monitor? Which do you drop? Which do you gate behind validation? ACA gives you the map; the architecture is your response.

## What's Not Solved

**ACA tells you what is controllable, not what will be attacked.** An attacker might not bother manipulating description text even though they could. ACA identifies the structural risk; threat intelligence tells you what adversaries actually do in practice.

**Partial controllability is hard to classify.** Some features (like tool outputs in an agent system) are partially controllable by the attacker. ACA treats these as a spectrum, but the binary classification (controlled vs not) is simpler to reason about. When in doubt, classify as attacker-controlled.

**ACA does not replace adversarial testing.** It tells you where to focus your testing budget. After mapping controllability, you should still run perturbation experiments on the attacker-controlled features to measure actual robustness. ACA just ensures you are not wasting time attacking features the adversary cannot reach.

The full ACA methodology, validated across six domains, is described in the [cross-domain perspective post](/posts/adversarial-control-analysis/) and demonstrated in [FP-01](https://github.com/rexcoleman/adversarial-ids-ml), [FP-02](https://github.com/rexcoleman/agent-redteam-framework), and [FP-05](https://github.com/rexcoleman/vuln-prioritization-ml).

---

> **Note (2026-03-19):** This was an early exploration in my AI security research. The methodology has known limitations documented in the [quality assessment](https://github.com/rexcoleman/Moonshots_Career_Thesis). For the current state of this work, see [Multi-Agent Security](https://github.com/rexcoleman/multi-agent-security) and [Verified Delegation Protocol](https://github.com/rexcoleman/verified-delegation-protocol).


*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

> **Note (2026-03-19):** This was an early exploration in my AI security research. The methodology has known limitations documented in the [quality assessment](https://github.com/rexcoleman/Moonshots_Career_Thesis). For the current state of this work, see [Multi-Agent Security](https://github.com/rexcoleman/multi-agent-security) and [Verified Delegation Protocol](https://github.com/rexcoleman/verified-delegation-protocol).


*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research -- findings, tools, and curated signal.*

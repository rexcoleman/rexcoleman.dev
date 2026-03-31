---
title: "AI Security Research → OWASP, NIST, and MITRE Standards Mapping"
date: 2026-03-31T12:00:00
description: "Cross-reference between 8 original AI security research projects and OWASP LLM Top 10, OWASP Agentic Apps, NIST AI RMF, and MITRE ATLAS. Start from any framework, find relevant research."
tags: ["ai-security", "owasp", "nist", "mitre-atlas", "standards-mapping", "compliance", "reference"]
keywords: ["OWASP LLM Top 10 research mapping", "NIST AI RMF security evaluation", "MITRE ATLAS AI security", "AI security standards compliance", "OWASP agentic applications research", "prompt injection OWASP mapping", "AI risk management framework research"]
categories: ["AI Security", "Research"]
format: "reference"
audience_side: "of-ai"
last_updated: "2026-03-31"
review_cadence: "6 months"
author: "Rex Coleman"
ShowToc: true
TocOpen: true
---

# AI Security Research → Standards Mapping

**Last updated: 2026-03-31**

A cross-reference between original AI security research and the frameworks practitioners use to assess, govern, and defend AI systems.

## Why This Mapping Exists

Security practitioners work within frameworks — Open Web Application Security Project (OWASP), National Institute of Standards and Technology (NIST), MITRE. Researchers often publish findings without connecting them to these frameworks, leaving practitioners to do the mapping themselves (or never find the research at all).

This document bridges that gap. Each project below produced original, multi-seed experimental findings on real Large Language Model (LLM) agents or real vulnerability data. The mapping shows exactly which standard categories each finding addresses, so you can find relevant research starting from whatever framework you already use.

All mappings are honest. Where a connection is approximate rather than direct, it is marked as indirect with a brief explanation. Where a project has no meaningful connection to a standard, the cell is left empty.

**External references:**
- [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [NIST AI Risk Management Framework (RMF)](https://www.nist.gov/artificial-intelligence/risk-management-framework)
- [MITRE Adversarial Threat Landscape for AI Systems (ATLAS)](https://atlas.mitre.org/)

---

## Quick Reference Table

| Research Project | Key Finding | OWASP LLM Top 10 | OWASP Agentic Apps | NIST AI RMF | MITRE ATLAS |
|---|---|---|---|---|---|
| Agent Semantic Resistance | Privilege escalation cascades hit 98%; domain-aligned attacks are invisible to defenses | LLM01 (Prompt Injection) | ASI01 (Agent Goal Hijack), ASI03 (Identity & Privilege Abuse) | MANAGE 2.2 (risk response), MEASURE 2.6 (monitoring) | AML.T0043 (Craft Adversarial Data — Prompt Injection), AML.T0051 (Exploit LLM Access) |
| LLM Watermark Robustness | Real Kirchenbauer watermarks (z=8.44) degrade under cross-model paraphrasing; single-pass paraphrase strips detectability | LLM09 (Misinformation) — indirect: watermark failure means AI-generated content provenance cannot be verified | — | GOVERN 1.2 (trustworthy AI characteristics), MAP 3.2 (benefits/costs of AI) | AML.T0047 (Evade Machine Learning (ML) Model) |
| ML Vulnerability Prioritization | ML matches Exploit Prediction Scoring System (EPSS) using only public data; Common Vulnerability Scoring System (CVSS) alone fails at exploit prediction (337K CVEs) | — | — | MEASURE 2.5 (AI system validity and reliability), MANAGE 1.3 (risk prioritization) | — |
| Multi-Agent Cascade Security | Simulation overestimates cascade by 37pp vs real agents; zero-trust cuts ~7pp (not 40pp); hierarchical topology is protective (0.560 vs flat 0.733) | LLM01 (Prompt Injection) | ASI01 (Agent Goal Hijack), ASI06 (Memory & Context Poisoning), ASI07 (Insecure Inter-Agent Communication), ASI08 (Cascading Failures) | MEASURE 2.5 (safety evaluation), MANAGE 2.2 (risk response) | AML.T0043 (Prompt Injection), AML.T0048 (indirect — a compromised agent acts as a poisoned component, not direct data poisoning) |
| Prompt Injection Taxonomy Across Frameworks | 65-78% injection success across 4 frameworks; indirect injection is framework-dependent (CrewAI 2x amplification) | LLM01 (Prompt Injection), LLM02 (Insecure Output Handling) | ASI01 (Agent Goal Hijack), ASI02 (Tool Misuse & Exploitation) | MEASURE 2.5 (safety evaluation), MAP 1.1 (intended purpose) | AML.T0043 (Prompt Injection), AML.T0040 (indirect — runtime injection via tool outputs creates a poisoned-input pathway, not training-time poisoning) |
| Verified Delegation Protocol | Verified delegation does NOT outperform no-defense on real agents; judge-aware adversary achieves 100% poison rate | LLM01 (Prompt Injection) | ASI01 (Agent Goal Hijack), ASI03 (Identity & Privilege Abuse) | MANAGE 2.4 (risk mitigation), MEASURE 2.6 (monitoring) | AML.T0043 (Prompt Injection), AML.T0044 (indirect — judge-aware adversary has defense knowledge analogous to white-box access, not full parameter access) |
| Agent-Assisted Vulnerability Triage | LLM agent achieves 92% precision@10 but EPSS (100%) outperforms solo agent; agent + EPSS ensemble reaches 98% — the value is in complementary signal | — | ASI03 (indirect — agent operates in security-critical decision loop with 8% error rate) | MEASURE 2.5 (AI system validity), MANAGE 2.2 (risk response) | AML.T0047 (indirect — unusual vulnerability descriptions could evade the triage model) |
| LLM-Generated Patch Correctness | 42% fix rate, 10% regression rate across 5 Common Weakness Enumeration (CWE) categories; extreme CWE-dependent variation (100% for weak crypto, much lower for injection flaws) | LLM02 (indirect — regression rate means LLM code output introduces new vulnerabilities, not classical output handling) | ASI02 (Tool Misuse & Exploitation — autonomous patch application exercises agency with measurable risk) | MEASURE 2.5 (safety evaluation), GOVERN 1.2 (trustworthy characteristics) | AML.T0047 (indirect — CWE-dependent variation suggests certain vulnerability patterns evade model understanding) |

---

## Per-Standard Detail

### OWASP Top 10 for LLM Applications (2025)

**LLM01 — Prompt Injection**

Five projects directly address prompt injection:

- **Agent Semantic Resistance** demonstrates that privilege escalation cascades succeed at 98% on real Claude Haiku agents, but domain-aligned attacks bypass defenses entirely. This quantifies the gap between known injection patterns and attacks that blend with legitimate agent context — the hardest variant of LLM01 to detect.
- **Multi-Agent Cascade Security** measures how injection propagates across multi-agent topologies. Zero-trust architecture reduces cascade by ~7 percentage points on real agents (not the 40pp that simulation predicted). Hierarchical topology provides more protection than trust model choice.
- **Prompt Injection Taxonomy Across Frameworks** is the most direct LLM01 mapping. Tests 20 payload types across LangChain, CrewAI, AutoGen, and direct Application Programming Interface (API). Finds 65-78% success rates and framework-dependent indirect injection behavior. LangChain is most vulnerable (78%), AutoGen least (65%).
- **Verified Delegation Protocol** tests whether a cryptographic delegation protocol can defend against LLM01 in multi-agent settings. Finding: it cannot. A judge-aware adversary achieves 100% poison rate, defeating the defense entirely.
- **LLM Watermark Robustness** addresses LLM01 indirectly — watermark stripping via paraphrasing is an output manipulation technique related to injection's goal of controlling model output.

**LLM02 — Insecure Output Handling**

- **Prompt Injection Taxonomy** finds that framework tool output handling directly determines indirect injection success. CrewAI's tool output processing amplifies indirect injection 2x vs direct — this is an insecure output handling pattern at the framework level.
- **LLM-Generated Patch Correctness** (indirect — the 10% regression rate means LLM-generated code outputs can introduce new vulnerabilities, which is not classical LLM02 but relevant to any system that executes LLM output as code).

**LLM09 — Misinformation**

- **LLM Watermark Robustness** (indirect — watermark failure means AI-generated content provenance cannot be verified; if watermarks can be stripped by a single paraphrase pass, there is no reliable mechanism to distinguish AI-generated from human-written content, enabling misinformation at scale).

### OWASP Top 10 for Agentic Applications (2026)

**ASI01 — Agent Goal Hijack**

Four projects map directly:

- **Agent Semantic Resistance** — domain-aligned injection hijacks agent goals on real agents
- **Multi-Agent Cascade Security** — injection propagation hijacks goals across agent topologies
- **Prompt Injection Taxonomy** — cross-framework injection success rates (goal hijack via prompt injection)
- **Verified Delegation Protocol** — defense failure against adaptive adversaries that hijack delegated agent goals

These four projects together provide a research arc: measure the baseline (Taxonomy), observe propagation (Multi-Agent Cascade), test defenses (Verified Delegation), and explain why some attacks evade all defenses (Semantic Resistance).

**ASI02 — Tool Misuse & Exploitation**

- **Prompt Injection Taxonomy** — indirect injection via tool outputs creates a tool exploitation pathway; CrewAI's tool output processing amplifies indirect injection 2x vs direct.
- **LLM-Generated Patch Correctness** — autonomous patch application exercises tool-mediated agency with measurable risk (10% regression rate). The agent misuses its code generation tool by introducing new vulnerabilities.

**ASI03 — Identity & Privilege Abuse**

- **Agent Semantic Resistance** — the 98% privilege escalation cascade rate directly measures identity and privilege abuse.
- **Verified Delegation Protocol** — delegation protocols are a privilege management mechanism; their failure means privilege abuse is not mitigated by this approach.
- **Agent-Assisted Vulnerability Triage** (indirect — agent operates in a security-critical decision loop with 8% error rate; the agent's identity/authority in the triage process carries risk).

**ASI06 — Memory & Context Poisoning**

- **Agent Semantic Resistance** — domain-aligned attacks poison agent context by blending with legitimate domain content, making the poisoned context invisible to defenses.
- **Multi-Agent Cascade Security** — cascade propagation poisons downstream agent context as compromised agents pass tainted information through the system.

**ASI07 — Insecure Inter-Agent Communication**

- **Multi-Agent Cascade Security** — directly measures how compromised agent communication propagates across topologies. The 37pp sim-to-real gap shows that inter-agent communication security behaves differently in real deployments.

**ASI08 — Cascading Failures**

- **Multi-Agent Cascade Security** — directly measures cascading failure across agent topologies. Hierarchical topology is protective (0.560 vs flat 0.733). Zero-trust reduces cascade by ~7pp on real agents.

### NIST AI Risk Management Framework

**MAP Function (Context and Scope)**

| Sub-category | Project | Relevance |
|---|---|---|
| MAP 1.1 — Intended purpose and context | Prompt Injection Taxonomy | Demonstrates that framework choice changes the attack surface — purpose and deployment context must include framework selection |
| MAP 1.5 — Organizational risk tolerances | — | — |
| MAP 3.2 — Benefits and costs | LLM Watermark Robustness | Watermark research quantifies the cost of provenance mechanisms |

**MEASURE Function (Assessment)**

| Sub-category | Project | Relevance |
|---|---|---|
| MEASURE 2.5 — Safety evaluation | Multi-Agent Cascade, Prompt Injection Taxonomy, LLM Patch Correctness, ML Vuln Prioritization, Agent-Assisted Vuln Triage | All five provide reproducible evaluation methodologies with multi-seed validation. The 37pp sim-to-real gap (Multi-Agent Cascade) is a direct warning about evaluation fidelity. ML Vuln Prioritization validates AI system reliability on 337K CVEs. Agent-Assisted Vuln Triage measures AI system validity (92% precision@10) |

| MEASURE 2.6 — Monitoring | Agent Semantic Resistance, Verified Delegation | Semantic Resistance shows domain-aligned attacks evade monitoring. Verified Delegation shows that verification-based monitoring fails against adaptive adversaries |

**MANAGE Function (Response)**

| Sub-category | Project | Relevance |
|---|---|---|
| MANAGE 1.3 — Risk prioritization | ML Vuln Prioritization | Provides data-driven risk prioritization methodology (337K CVEs) that directly informs organizational risk prioritization |
| MANAGE 2.2 — Risk response | Agent Semantic Resistance, Multi-Agent Cascade, Agent Vuln Triage | Three projects provide data for risk response decisions: what works (topology, ensembles), what doesn't (verified delegation), and what remains undetectable (domain-aligned attacks) |
| MANAGE 2.4 — Risk mitigation | Verified Delegation | Negative result — demonstrates that a specific mitigation approach (verified delegation) fails. Negative results are critical for risk management because they prevent investment in ineffective controls |

**GOVERN Function (Organizational)**

| Sub-category | Project | Relevance |
|---|---|---|
| GOVERN 1.2 — Trustworthy AI characteristics | LLM Watermark Robustness, LLM Patch Correctness | Watermark research addresses provenance and authenticity. Patch research addresses reliability (42% fix rate) and safety (10% regression rate) — both core trustworthiness characteristics |

### MITRE ATLAS

Technique IDs below use the Adversarial Machine Learning (AML) prefix from the ATLAS taxonomy.

**AML.T0043 — Craft Adversarial Data: Prompt Injection**

This is the primary ATLAS technique for four projects:

- **Agent Semantic Resistance** — taxonomy of injection types by semantic alignment
- **Multi-Agent Cascade Security** — injection propagation measurement
- **Prompt Injection Taxonomy** — cross-framework injection success quantification
- **Verified Delegation Protocol** — defense evaluation against injection

**AML.T0047 — Evade ML Model**

- **LLM Watermark Robustness** — cross-model paraphrasing as an evasion technique against watermark detection
- **Agent-Assisted Vulnerability Triage** (indirect — the 8% error rate represents cases where adversarial or unusual vulnerability descriptions could evade the triage model, not classical ML evasion)
- **LLM-Generated Patch Correctness** (indirect — CWE-dependent variation suggests certain vulnerability patterns evade the model's understanding, not adversarial evasion per se)

**AML.T0051 — Exploit LLM Access**

- **Agent Semantic Resistance** — privilege escalation cascades exploit the agent's tool access and authority to propagate through the system

**AML.T0040 — Model Poisoning**

- **Prompt Injection Taxonomy** (indirect — technically runtime injection rather than training-time poisoning, but indirect injection via tool outputs creates a poisoned-input pathway analogous to data poisoning)

**AML.T0044 — Full ML Model Access**

- **Verified Delegation Protocol** (indirect — the judge-aware adversary has knowledge of the defense mechanism, analogous to white-box model access but not full parameter access)

**AML.T0048 — Data Poisoning via Compromised Component**

- **Multi-Agent Cascade Security** (indirect — a compromised agent in a multi-agent system acts as a compromised component that poisons downstream agents, not classical supply-chain data poisoning)

---

## How to Use This Mapping

**If you are implementing OWASP LLM Top 10 controls:**
Start with the Prompt Injection Taxonomy project for baseline attack success rates across frameworks. Use Multi-Agent Cascade Security to understand how injection propagates. Review Agent Semantic Resistance for the attack types your monitoring will miss.

**If you are conducting an OWASP Agentic Applications threat assessment:**
The four ASI01 projects provide a complete research arc from measurement to defense evaluation. For ASI02 (Tool Misuse & Exploitation), the Prompt Injection Taxonomy and LLM Patch Correctness projects quantify framework-level and code-generation risks. For ASI03 (Identity & Privilege Abuse), Agent Semantic Resistance provides direct measurements. For ASI08 (Cascading Failures), Multi-Agent Cascade Security measures real vs simulated cascade severity.

**If you are mapping to NIST AI RMF:**
The MEASURE function has the strongest coverage — three projects provide reproducible evaluation methodologies. The 37pp simulation-to-real gap (Multi-Agent Cascade) is particularly relevant for organizations relying on simulated evaluations. For MANAGE, four projects provide data for risk response decisions.

**If you are building a MITRE ATLAS threat model:**
Five projects map to AML.T0043 (Prompt Injection) with different experimental conditions. Use the Prompt Injection Taxonomy for framework-specific threat modeling. Use Multi-Agent Cascade for topology-aware threat modeling.

**If you are a red team:**
The Prompt Injection Taxonomy provides 20 payload types with measured success rates. Agent Semantic Resistance identifies domain-aligned attacks as the highest-impact, lowest-detection vector. The 37pp sim-to-real gap warns that your simulation-based testing overestimates real attack severity.

**If you are a blue team:**
Verified Delegation Protocol is a critical negative result — do not invest in delegation-based defenses without addressing the judge-aware adversary attack. Hierarchical topology (Multi-Agent Cascade) provides measurable protection. Agent + EPSS ensemble (Agent-Assisted Vulnerability Triage) provides the best triage accuracy.

---

## Methodology Notes

- All projects used multi-seed experimental designs (3-5 seeds) with pre-registered hypotheses
- Projects testing real LLM agents used Claude 3 Haiku as the base model
- Quality scores range from 7.6 to 9.0 (scored by automated quality gates)
- Negative results are included and clearly labeled — these are often the most valuable findings for practitioners
- Mappings marked "(indirect — ...)" indicate the research is relevant but not a direct instance of the standard category, with an explanation of the relationship

---

*Rex Coleman builds and attacks AI security systems at every layer of the stack — then publishes the methodology so others can too. More research at [rexcoleman.dev](https://rexcoleman.dev).*

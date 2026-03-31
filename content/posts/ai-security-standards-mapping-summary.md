---
title: "We Mapped 8 AI Security Research Projects to OWASP, NIST, and MITRE — Here's Where the Gaps Are"
date: 2026-03-31T13:00:00
description: "Independent research mapped to the frameworks practitioners actually use. Five projects address OWASP LLM01 (Prompt Injection) — but LLM03, LLM07, and LLM08 have zero research coverage."
tags: ["ai-security", "owasp", "nist", "mitre-atlas", "standards-mapping"]
keywords: ["OWASP LLM Top 10 coverage gaps", "AI security research standards mapping", "NIST AI RMF research", "prompt injection OWASP research"]
categories: ["AI Security"]
format: "blog"
audience_side: "of-ai"
author: "Rex Coleman"
ShowToc: false
image_count: 0
---

Five of eight research projects map to OWASP LLM01 (Prompt Injection). Three OWASP categories — LLM03 (Supply Chain), LLM07 (System Prompt Leakage), and LLM08 (Vector/Embedding Weaknesses) — have zero research coverage. That gap tells you where the next round of experiments needs to go.

I published a [full standards mapping](/posts/ai-security-standards-mapping/) that cross-references 8 original AI security research projects against four frameworks. The mapping covers OWASP Top 10 for Large Language Model (LLM) Applications, OWASP Top 10 for Agentic Applications, National Institute of Standards and Technology (NIST) AI Risk Management Framework (RMF), and MITRE Adversarial Threat Landscape for AI Systems (ATLAS).

## Why this matters

Security practitioners work within frameworks. Researchers publish findings without connecting to those frameworks. The result: practitioners don't find relevant research, and researchers don't know which standards their work addresses.

This mapping bridges that gap. Start from whatever framework you use — OWASP, NIST, MITRE — and find the research that applies.

## Key findings from the mapping

**Prompt injection dominates the research portfolio.** Five of eight projects address LLM01, with measured success rates from 65% to 98% across different conditions. The hardest variant — domain-aligned attacks that blend with legitimate content — has a 0% detection rate.

**The OWASP Agentic Apps standard (2026) has strong coverage.** Four projects map to ASI01 (Agent Goal Hijack), providing a complete arc from measurement to defense evaluation. ASI07 (Insecure Inter-Agent Communication) and ASI08 (Cascading Failures) have direct experimental data.

**NIST AI RMF MEASURE function is the strongest mapping.** Five projects provide reproducible evaluation methodologies. The 37 percentage-point simulation-to-real gap (Multi-Agent Cascade Security) is a direct warning for organizations relying on simulated evaluations.

**Negative results are the most valuable entries.** Verified Delegation Protocol fails against judge-aware adversaries. Machine Learning (ML) Vulnerability Prioritization shows the Exploit Prediction Scoring System (EPSS) outperforms a solo LLM agent. These findings prevent investment in approaches that don't work.

## Coverage gaps

| OWASP Category | Coverage |
|---|---|
| LLM01 — Prompt Injection | 5 projects |
| LLM02 — Insecure Output Handling | 2 projects |
| LLM09 — Misinformation | 1 project (indirect) |
| LLM05 — Supply Chain Vulnerabilities | 0 projects |
| LLM07 — System Prompt Leakage | 0 projects |
| LLM08 — Vector and Embedding Weaknesses | 0 projects |

The gaps are where the next experiments go.

## Full mapping

The [complete standards mapping](/posts/ai-security-standards-mapping/) includes per-standard detail sections, NIST AI RMF function tables, MITRE ATLAS technique mappings, and a "How to Use This Mapping" guide for CISOs, red teams, and blue teams.

---

*Rex Coleman builds and attacks AI security systems at every layer of the stack — then publishes the methodology so others can too. More research at [rexcoleman.dev](https://rexcoleman.dev).*

---
title: "Your Agent's Biggest Security Problem Isn't Prompt Injection — It's Whether You're Watching"
date: 2026-04-01
draft: true
categories: ["AI Security"]
tags: ["agent-security", "owasp", "benchmark", "observability", "controllability", "ai-security", "research"]
image_count: 1
format: "findings"
featured: false
audience_side: "of-ai"
description: "We built the first benchmark for the OWASP Agentic Top 10 and found that defense observability predicts 96.5% of vulnerability severity. The first defense layer captures 90% of the improvement."
---

Last month I ran a prompt injection attack against a LangChain agent with access to a code execution tool. The attack succeeded — not because the injection was clever, but because the agent had no input filtering, no output checking, and no action logging. There was nothing watching.

That experience matched a pattern I'd been seeing across [five research projects](https://rexcoleman.dev) in agent security: the presence of *any* defense mechanism matters more than the sophistication of the defense. So I built a benchmark to test it.

## The benchmark

[OWASP Agent Bench](https://github.com/rexcoleman/owasp-agent-bench) maps five OWASP Agentic Top 10 categories to 25 standardized test cases, each scored for severity across three defense configurations: permissive (no defenses), validated (filters + logging), and zero-trust (allowlists + limits).

```bash
pip install owasp-agent-bench
owasp-agent-bench run
```

The benchmark complements the UK AI Safety Institute's [AgentThreatBench](https://github.com/UKGovernmentBEIS/inspect_evals/issues/1031), which covers three different OWASP categories with live agent testing. Our approach is different: we evaluate architectural security properties — does the agent framework filter inputs? Restrict tool access? Log actions? — and use a formal model to PREDICT severity from architecture alone. Results are deterministic and reproducible without an API key.

## What I found

I pre-registered a controllability model that predicts severity from two architectural variables: how much an attacker controls (C) and how much a defender monitors (D). The additive model `severity ≈ w₀ + w₁·C + w₂·(1-D)` predicts benchmark severity with R²=0.967 across all five OWASP categories.

Here's where it gets interesting: **defense observability alone predicts 96.5% of severity variance.** Attacker controllability adds just 0.2% more.

![Severity heatmap across OWASP categories and trust levels](/images/owasp-bench-heatmap.png)
*Severity drops precipitously from permissive to validated — the first defense layer does most of the work.*

Three numbers that matter for practitioners:

- **12:1 ratio** — observability weight (0.740) vs controllability weight (0.063) under the benchmark's test conditions. Sensitivity analysis shows this is amplified by limited C range, but observability still leads.
- **90% from the first layer** — a binary "has any defense?" heuristic achieves R²=0.900. Going from zero defenses to one defense captures most of the security improvement.
- **3:1 diminishing returns** — moving from permissive to validated reduces severity by 0.59. Moving from validated to zero-trust reduces it by only 0.20.

## What this means for your agent deployment

If you're deploying an AI agent today, the research says: **start with monitoring, not with prompt hardening.**

1. **Add input validation first.** Even basic keyword filtering dramatically reduces severity across all OWASP categories. You don't need sophisticated prompt injection detection — you need *anything*.

2. **Add output checking second.** Sensitive data detection on agent outputs catches the majority of data leakage attacks.

3. **Add action logging third.** Knowing what the agent did is half of knowing whether it was compromised.

4. **Tool restriction is high-value but comes after monitoring.** Allowlisting tools (zero-trust) is the strongest defense, but adds less marginal value than the first two steps.

Prompt hardening — making the system prompt more resistant to injection — addresses the controllability variable (C), which accounts for a much smaller share of severity than observability.

## The honest caveat

This result comes with a sensitivity caveat I committed to reporting: the 12:1 observability dominance is partially an artifact of restricted controllability range in the test conditions. When I extended C variance with synthetic conditions, the ratio dropped to 1.2:1. Observability still leads, but not by the margin the headline number suggests.

The additive structure itself is robust — defense layers compose additively (R²=0.967), not multiplicatively (R²=0.893). This extends to web application security too: running the same model on OWASP Web Top 10 data yields R²=0.954.

## Try it

The benchmark is open source and pip-installable:

```bash
pip install owasp-agent-bench

# Run the full benchmark
owasp-agent-bench run

# Score a specific category
owasp-agent-bench run --category prompt_injection

# Predict severity from architecture
owasp-agent-bench predict --C 0.8 --D 0.2
```

Five OWASP categories are currently covered. The remaining five are designed but unimplemented — contributions welcome.

The research paper is available on [arXiv](#) (link pending submission).

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman)*

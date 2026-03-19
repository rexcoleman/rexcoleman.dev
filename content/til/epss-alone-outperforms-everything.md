---
title: "EPSS alone outperforms all other vuln prediction features combined"
date: 2026-03-19
draft: false
tags: ["vulnerability-management", "machine-learning", "epss", "ablation-study"]
format: "til"
audience_side: "from-ai"
---

**In ablation testing of an ML vulnerability prioritization model, removing EPSS (Exploit Prediction Scoring System) dropped performance by 15.5 percentage points.** No other single feature — not CVSS, not vendor, not CWE, not exploit availability — came close. EPSS alone carries more predictive signal than every other feature combined.

## Why this matters

Most vulnerability management programs still use CVSS as their primary prioritization input. CVSS measures theoretical severity. EPSS measures observed exploitation probability. When you build an ML model that can use both (plus dozens of other features), EPSS dominates. This isn't a marginal improvement — it's a structural finding about where the real signal lives.

## Source

This comes from the ablation study in [FP-05 (Vulnerability Prioritization ML)](/posts/cvss-gets-it-wrong/), where I trained gradient-boosted models on 200K+ CVE records and systematically removed features to measure their individual contribution. Full code and data: [github.com/rexcoleman/vuln-prioritization-ml](https://github.com/rexcoleman/vuln-prioritization-ml).

## What to do about it

1. **If you're not using EPSS, start today.** It's free, updated daily, and available via API at [first.org/epss](https://www.first.org/epss/).
2. **Don't replace CVSS — complement it.** CVSS tells you how bad a vuln could be. EPSS tells you how likely someone is actually exploiting it.
3. **If you're building ML models for vuln prioritization,** make EPSS your first feature and work outward from there. The marginal value of additional features is real but modest compared to getting EPSS right.

The vulnerability management field has a signal problem, not a data problem. EPSS is where the signal is.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

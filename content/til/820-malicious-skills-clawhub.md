---
title: "820 malicious skills on ClawHub: 1 in 5 is hostile"
date: 2026-03-19
draft: false
tags: ["agent-security", "supply-chain", "openclaw", "signal-report"]
format: "til"
audience_side: "of-ai"
---

**820+ malicious skills have been identified on ClawHub, the OpenClaw marketplace.** That means roughly 1 in 5 skills listed in the registry is hostile — designed to exfiltrate data, inject commands, or establish persistence in your agent environment.

## Why this matters

ClawHub is where most OpenClaw users discover and install third-party skills. It is the npm/PyPI of the agent economy, and it has the same supply chain poisoning problem those ecosystems faced — except worse. Agent skills don't just run code at install time. They execute continuously during agent operation, with access to your terminal, filesystem, and API credentials. A malicious skill doesn't need a clever exploit chain. It just needs you to install it.

## Source

This finding comes from [Signal Report #1](/posts/signal-report-001/), which aggregated community signal data across HN, GitHub, security blogs, and vendor reports in Q1 2026. The 820 figure was corroborated across multiple independent scanning efforts of the ClawHub registry.

## What to do about it

1. **Never install third-party skills without review.** Read the source code. If it's obfuscated, skip it.
2. **Pin skill versions.** Don't auto-update skills from the marketplace.
3. **Run agents in sandboxed environments.** NanoClaw provides container-level isolation, but it doesn't monitor behavior inside the container.
4. **Watch for the tooling gap.** Existing scanners range from bash+grep (SkillVet [HYPOTHESIZED]) to enterprise-weight (Cisco). A middle ground is emerging but not yet mature.

The agent supply chain is the new software supply chain. The attack surface is real, the tooling is immature, and the defaults are dangerous.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

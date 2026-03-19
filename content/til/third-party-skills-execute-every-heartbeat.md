---
title: "Third-party skills execute every heartbeat — not once"
date: 2026-03-19
draft: false
tags: ["agent-security", "openclaw", "supply-chain", "runtime-security"]
format: "til"
audience_side: "of-ai"
---

**When you install a third-party OpenClaw skill, it doesn't just run at install time. It executes on every agent heartbeat** — every loop iteration where the agent checks its environment, processes inputs, and decides what to do next. A malicious skill gets continuous execution, not a one-shot opportunity.

## Why this matters

Most developers think of skill installation like installing a library: it runs setup once, then sits there until called. That mental model is wrong for agent skills. Agent architectures run skills as part of their core loop. This means a malicious skill gets persistent, repeated access to the agent's context, memory, filesystem, and network connections — not just a single execution window.

## Source

This comes from research into the [OpenClaw architecture](/posts/secure-openclaw-30-minutes/) and Alex Finn's operational guidance (SRC-111). The heartbeat execution model is a fundamental design choice in how OpenClaw agents process skills.

## What to do about it

1. **Treat every installed skill as a persistent background process**, not a one-time script.
2. **Never install third-party skills** you haven't read the source code for. This is the single biggest attack vector in the agent ecosystem.
3. **Build or use locally** whenever possible. The safest skill is one you wrote yourself.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

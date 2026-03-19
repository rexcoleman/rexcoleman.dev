---
title: "Reasoning chain hijacking has 100% success rate on default LangChain"
date: 2026-03-19
draft: false
tags: ["ai-security", "agent-security", "langchain", "prompt-injection", "red-team"]
format: "til"
audience_side: "of-ai"
---

**In red-team testing of AI agent frameworks, reasoning chain hijacking attacks achieved a 100% success rate against default LangChain configurations.** Every single attempt to inject instructions into the agent's chain-of-thought reasoning succeeded in altering the agent's behavior.

## Why this matters

Reasoning chain hijacking is different from basic prompt injection. Instead of injecting a single malicious instruction, the attacker injects a plausible reasoning chain that guides the agent through a series of "logical" steps toward the attacker's goal. The agent follows the injected chain because it looks like its own reasoning. Default LangChain configurations have no defense against this — no chain validation, no reasoning integrity checks, no anomaly detection on thought patterns.

## Source

This comes from [FP-02 (Agent Red-Team Framework)](/posts/agent-redteam/), where I tested 7 attack classes against multi-step AI agents with 5 defense configurations. Full code: [github.com/rexcoleman/agent-redteam-framework](https://github.com/rexcoleman/agent-redteam-framework).

## What to do about it

1. **Never deploy LangChain agents with default settings** in any environment where adversarial inputs are possible (which is most environments).
2. **Implement reasoning chain validation.** Compare intermediate reasoning steps against expected patterns or constrained output schemas.
3. **Layer defenses.** In my testing, combining input filtering + output validation + chain verification reduced success rates significantly — but no single defense was sufficient alone.

If your agents use chain-of-thought reasoning and accept external input, you have this vulnerability. Test it before someone else does.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

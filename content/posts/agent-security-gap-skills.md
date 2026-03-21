---
title: "The Agent Security Gap Nobody's Talking About: Skills Run Every Heartbeat"
date: 2026-03-19
draft: false
tags: ["agent-security", "supply-chain", "openclaw", "singularity-cybersecurity", "skills-security"]
categories: ["AI Security", "Builder Journal"]
format: "perspective"
audience_side: "of-ai"
image_count: 0
description: "Everyone's worried about prompt injection, but the real agent attack surface is third-party skills — they execute persistently on every heartbeat cycle."
aliases:
  - /research/state-of-agent-security-q1-2026/
author: "Rex Coleman"
ShowToc: true
TocOpen: true
cover:
    image: /images/og-agent-security-gap-skills.png
    hidden: true
---

**Thesis:** Everyone's worried about prompt injection, but the real agent attack surface is third-party skills — they execute persistently on every heartbeat cycle, not once per conversation.

I keep having the same conversation. Someone asks about agent security. I say "third-party skills." They say "you mean prompt injection?" No. I mean the code that runs inside your agent 144 times per day, with full access to your agent's memory, context, and credentials, that you installed from a marketplace where one in five entries is actively malicious.

Prompt injection is a conversation-level attack. Skills are an infrastructure-level attack. The security community is focused on the wrong layer.

## The Evidence

**1. 820+ malicious skills on ClawHub — 20% of the registry.**

ClawHub is the largest agent skill marketplace. Community analysis shows 820+ malicious skills out of roughly 4,000 total. That's not a rounding error — it's a 20% infection rate. For comparison, the worst npm supply chain incidents involved dozens of malicious packages out of millions. ClawHub's ratio is orders of magnitude worse.

These aren't theoretical risks. The malicious skills fall into three categories I've documented: data exfiltration skills that scan for API keys and tokens on every heartbeat, behavior modification skills that subtly alter agent reasoning, and lateral movement skills that use the agent as a platform to attack connected systems. The sophisticated ones provide real functionality — "memory optimizer," "context analyzer" — while exfiltrating data through the agent's own web browsing capabilities. The traffic looks like normal agent activity.

**2. Skills bypass every guardrail designed for prompt-level attacks.**

Here's the architectural difference that matters:

| Property | Prompt Injection | Malicious Skill |
|----------|-----------------|-----------------|
| **Execution frequency** | Once per malicious input | Every heartbeat cycle (144x/day at 10-min intervals) |
| **Exposure window** | Seconds (single conversation turn) | Indefinite (until uninstalled) |
| **Access scope** | Current conversation context | Full agent memory, all credentials, all tools |
| **Visibility** | Appears in conversation log | Runs silently in background |
| **Guardrail coverage** | Input sanitization, output filtering | None — runs as trusted internal code |
| **Detection method** | Text pattern matching | Behavioral analysis (doesn't exist yet) |
| **Persistence** | Ends when conversation ends | Persists across all sessions |

Prompt injection defenses — input sanitization, guardrails, output validation — operate on the text layer. They inspect what goes into the agent's reasoning and what comes out. A malicious skill doesn't enter through the text layer. It's installed as trusted code. It runs inside the agent's execution loop. Guardrails don't see it because it's not a prompt — it's infrastructure.

This is the equivalent of building a firewall and then giving the attacker a shell account on the server. The firewall is working perfectly. The threat isn't coming through the firewall.

**3. No scanning tools exist for behavioral skill analysis.**

VirusTotal can't detect agent-specific malware — 6,487 malicious agent tools evade traditional scanners because they use legitimate agent APIs to produce malicious outcomes. Static analysis tools (including Cisco's LLM-based skill-scanner) can catch obvious patterns — hardcoded exfiltration URLs, suspicious network calls in source code. But the hardest malicious skills contain clean code that produces malicious behavior through legitimate API combinations.

This is the same gap the endpoint security industry faced 15 years ago: antivirus (pattern matching) couldn't catch fileless malware and living-off-the-land attacks. The industry built EDR (behavioral detection) to close the gap. Agent skill security is in the antivirus era. We need EDR-equivalent behavioral analysis — sandbox the skill, observe what it does across multiple heartbeat cycles, flag anomalous patterns — and it doesn't exist as a product.

**4. 30 MCP CVEs in 60 days. 66% of servers have findings. 492 with zero auth.**

The MCP ecosystem — the protocol layer that skills use to connect to external services — accumulated 30 CVEs in its first 60 days. A scan of 1,808 MCP servers found 66% had security findings. 492 servers had no authentication or encryption whatsoever.

Skills connect through MCP servers. If the skill is malicious and the MCP server has no auth, the attack chain is: install skill from ClawHub (20% chance it's malicious) → skill connects to MCP server (66% chance it has vulnerabilities) → skill exfiltrates data through the MCP connection (492 servers with zero auth). Every link in this chain is broken, and the chain is the default deployment path.

**5. The first agent-framework RCE is already here.**

CVE-2026-25253 — the first remote code execution vulnerability in an agent framework. Not a skill. Not a plugin. The framework itself. Combined with the ClawJacked attack (CVE-2026-21852), which achieves 1-click RCE via WebSocket origin bypass on local agents, the attack surface extends beyond skills to the agent runtime.

But skills remain the primary vector because they don't require a vulnerability. A malicious skill exploits the design of the system, not a bug in it. The agent is working correctly — executing the skill it was told to execute. The skill is the attack.

## What This Means for the Field

The agent security conversation is stuck on prompt injection because that's the attack everyone understands. It maps cleanly to existing mental models: input goes in, bad thing happens, filter the input. Security teams know how to think about input validation.

Skills don't fit that model. They're not input. They're code. They don't happen once. They run continuously. They don't bypass guardrails through cleverness. They bypass guardrails by existing at a layer the guardrails don't cover.

The mental model shift the field needs: agents aren't chatbots with tools. Agents are execution environments that run third-party code. The security model should be closer to container security and software supply chain security than to prompt filtering. The question isn't "how do we sanitize inputs?" It's "how do we verify that every piece of code running inside our agent is trustworthy, continuously?"

Until the field makes that shift, the 820+ malicious skills on ClawHub will keep growing. Because nobody's scanning for them.

## What I'm Doing About It

At [Singularity Cybersecurity](https://singularitycyber.com), we're building two tools to close this gap:

**SkillVet [HYPOTHESIZED]** — behavioral sandbox scanning. Instead of pattern-matching skill source code, SkillVet runs skills in an instrumented sandbox and observes their behavior across multiple heartbeat cycles. It watches for data exfiltration patterns, memory modification, credential access, and anomalous network activity. The goal: catch the skills that static analysis misses because their code is clean but their behavior is hostile.

**AgentArmor [HYPOTHESIZED]** — runtime behavioral monitoring. SkillVet catches threats pre-install. AgentArmor catches them post-install. It monitors what skills actually do during live agent operation — file access patterns, API calls, network traffic, memory modifications — and alerts on behavioral anomalies. This is the EDR equivalent for agent skill security.

The practical first step is published: [How to Secure Your OpenClaw in 30 Minutes](/posts/secure-openclaw-30-minutes/). Rule #1: don't install third-party skills. Read the source, rebuild locally, control your own code. That doesn't scale — which is why we're building the tools.

### Limitations

The 820 malicious skill count comes from community reporting and ClawHub registry analysis, not independent verification. ClawHub's moderation practices and detection rates are not publicly documented. The "20% infection rate" assumes a total registry of approximately 4,000 skills, which may have changed. The 144x/day heartbeat execution assumes a 10-minute heartbeat interval; different configurations will produce different numbers. The comparison to prompt injection is analytical — no controlled experiment directly quantifies the differential risk.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

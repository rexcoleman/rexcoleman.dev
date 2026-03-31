---
title: "5 AI Security Gaps That Jensen Huang, Eric Schmidt, and the OpenClaw Creator All Flagged This Month"
date: 2026-03-29T16:00:00
description: "I analyzed 5 frontier podcasts for AI security signals. Three independent sources converged on the same gaps — and NVIDIA already shipped a fix for one."
tags: ["agent-security", "ai-security", "market-signals", "multi-agent", "supply-chain"]
keywords: ["Jensen Huang AI security NVIDIA", "Eric Schmidt agent security concerns", "openclaw security vulnerabilities 2026", "AI agent prompt injection unsolved", "multi-agent orchestration security risks"]
categories: ["AI Security"]
featured: false
format: "perspective"
audience_side: "of-ai"
image_count: 0
author: "Rex Coleman"
ShowToc: true
TocOpen: false
---

I spent this week extracting AI security signals from five frontier podcasts — Jensen Huang on Lex Fridman, Eric Schmidt on Moonshots, Peter Steinberger (OpenClaw creator) on Lex Fridman, and two Moonshots panel episodes covering NVIDIA, Anthropic, and Tesla. 68 claims, 30 concepts, 26 signals logged to a structured knowledge base.

The finding that surprised me: **three independent sources — a $4 trillion CEO, a former Google CEO, and the creator of the fastest-growing open-source project in history — all flagged the same security gaps without coordinating.** Here are the five signals that converged.

## 1. Multi-Agent Orchestration Is a Recognized Security Problem

Eric Schmidt [told Congress](/posts/agent-semantic-resistance/) and the Moonshots podcast: combining agents from incompatible vendors produces "unpredictable effects." This isn't theoretical concern — it's a former Google CEO warning about a specific failure mode in production systems.

Jensen Huang validated this from the infrastructure side. NVIDIA shipped security controls for OpenClaw (called OpenShell/NemoClaw) **within days** of its release. Their design: a "two-out-of-three" capability constraint where agents can have at most two of three rights — sensitive data access, code execution, and external communication. Never all three simultaneously.

**Why this matters for AI builders:** If you're orchestrating agents from multiple providers (Claude for reasoning, GPT for code generation, local models for privacy-sensitive tasks), the interaction effects aren't just performance issues. They're security surfaces. Schmidt isn't speculating — he's describing what his network is seeing in production.

My [multi-agent cascade research](/posts/agent-semantic-resistance/) found a 98 percentage-point spread in attack success rates across payload types. The agents that resist one attack class are completely blind to another. Combining agents doesn't average out the vulnerabilities — it can compound them.

## 2. Prompt Injection Remains Unsolved at Industry Scale

Lex Fridman called OpenClaw "a security minefield." Peter Steinberger agreed and was more specific: prompt injection is "still an open problem industry-wide."

Steinberger's insight was the most actionable: **weaker models are dramatically more vulnerable.** His advice to users: "Don't use cheap models. Don't use Haiku or a local model... very gullible." But there's a three-dimensional trade-off at play — as models get smarter, the attack surface decreases but damage potential increases.

The current state of agent security? VirusTotal partnership for skill scanning and AI-based review of markdown files. Steinberger acknowledged this is first-generation. His next focus after the podcast is explicitly security hardening.

**What this means:** The creator of the most popular AI agent in history is telling you his security is primitive and he's working on it next. The gap between agent capability and security tooling is at maximum width right now.

## 3. Supply Chain Attacks on Agent Ecosystems Are Real and Fast

When OpenClaw renamed (from its previous name), threat actors sniped the old GitHub account, NPM packages, and Twitter handles **within seconds** to serve malware. Not hours. Seconds.

This isn't the same class of supply chain attack as the SolarWinds or Log4j incidents. Agent ecosystem supply chains move faster, have more entry points (skills defined in markdown, plugin registries, model endpoints), and the attack surface is orders of magnitude simpler to exploit. A malicious skill file is just a markdown document with hidden instructions.

Meanwhile, Xiaomi's trillion-parameter "Hunter Alpha" model appeared anonymously on OpenRouter — no attribution, no press release — and processed 160 billion tokens before anyone identified who built it. Model provenance is failing.

**The practical concern:** If you're installing agent skills from a marketplace, or connecting to model endpoints you didn't deploy, you're trusting a supply chain that has demonstrated real-time attack capability.

## 4. Enterprise AI Governance Has No Tooling

Dave Blundin (serial entrepreneur, investor) stated it bluntly on Moonshots: "Do not reimburse people for AI that you can't see. Make sure it's on your infrastructure."

Companies are now tracking individual employee AI token usage, targeting 80% token cost / 20% salary ratios. Jensen Huang's benchmark: a $500K engineer should consume at least $250K in AI tokens. This means prompt histories — containing proprietary reasoning, competitive strategies, and decision patterns — are becoming the primary record of employee intellectual output.

Peter Steinberger said audit logs "seem like an enterprise feature" he can't prioritize in OpenClaw. Enterprise agent security is explicitly deprioritized by the open-source ecosystem.

**The gap:** Shadow AI (employees using personal AI accounts for work), unlogged agent sessions, prompt histories flowing outside DLP controls — enterprises are deploying AI agents at scale with governance infrastructure designed for the pre-agent era.

## 5. Overnight Agent Sessions Have Zero Oversight

Schmidt described a pattern that's becoming common among AI-forward developers: launch coding jobs at 7 PM, review results at breakfast. Steinberger built OpenClaw's "Heartbeat" feature — cron-triggered autonomous agent action without a human prompt.

These patterns mean AI agents are operating for hours with zero human oversight, making decisions, executing code, and potentially communicating externally. The security question isn't whether these sessions produce good code — it's whether anyone would notice if they did something unexpected at 3 AM.

**Why this is harder than it sounds:** The failure mode of a compromised overnight agent session is indistinguishable from normal operation until the output is reviewed. Traditional monitoring (CPU usage, network traffic, error rates) won't catch an agent that's doing the wrong thing correctly.

## The Meta-Signal

Jensen Huang says AGI is here now. Schmidt says we're 10-15% into AI's total impact. Steinberger says 2026 is the year of personal agents. The programmer population is expanding from 30 million to potentially 1 billion as "coding" becomes "specification."

Every one of these trends expands the attack surface for AI security. And the people building the systems are the ones flagging the gaps.

The question isn't whether AI security tooling is needed. It's whether it arrives before the first major incident that Schmidt delicately called a "modest Chernobyl."

---

## What I'm Doing About It

These signals validate the exact problems I've been researching. My [multi-agent cascade experiments](/posts/agent-semantic-resistance/) quantify the 98-percentage-point spread in attack success rates that Schmidt is warning about. My [agent security gap analysis](/posts/agent-security-gap-skills/) maps the skill/plugin attack surfaces that Steinberger's VirusTotal partnership only partially addresses. And our [simulation-to-real validation](/posts/multi-agent-security/) proved that real agents resist cascade differently than simulations predict — the gap was 37 percentage points. NVIDIA's two-out-of-three capability constraint is a pattern I'm now testing against zero-trust approaches in a multi-agent testbed.

The research continues: agent skill security scanning, model-tiered injection benchmarks, and supply chain monitoring for agent ecosystems are all in design.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

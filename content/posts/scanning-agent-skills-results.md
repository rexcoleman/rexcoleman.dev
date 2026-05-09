---
title: "We Scanned 40 Agent Skills for Security Issues — Here's What We Found"
date: 2026-04-12
description: "22 security findings across 40 real OpenClaw agent skills. Data exfiltration patterns dominated, but the most interesting result was what the scanner got wrong."
tags: ["ai-security", "mcp", "agent-security", "security-scanning"]
keywords: ["agent skill security scan", "openclaw skill vulnerability", "MCP security scanning", "agent supply chain security", "AI agent skill scanner results"]
categories: ["AI Security", "Research"]
format: "technical-blog"
audience_side: "of-ai"
author: "Rex Coleman"
ShowToc: true
TocOpen: false
draft: true
---

We ran [agent-skill-scanner](https://github.com/rexcoleman/agent-skill-scanner) against 40 real OpenClaw agent skills downloaded from the community. 22 detection rules across 5 categories: prompt injection, capability escalation, data exfiltration, encoded payloads, and composition risks. Here's what the scanner found — and where it was wrong.

## What We Scanned

The dataset: 40 curated OpenClaw skills from public repositories. These are real skills that real agents install and run — not synthetic test cases. They include API wrappers, utility tools, games, integrations, and one security defense skill.

The scanner parses each skill's YAML frontmatter, markdown body, and code blocks, then runs pattern-based detection against 22 rules. It's static analysis — no execution, no LLM reasoning, just pattern matching. That distinction matters, and we'll come back to it.

## Results Summary

**33 of 40 skills (82%) were clean.** No findings at any severity level.

**7 skills (18%) triggered at least one finding**, producing 22 total findings:

| Category | Findings | % of Total |
|----------|----------|------------|
| Data exfiltration | 14 | 64% |
| Prompt injection | 4 | 18% |
| Capability escalation | 3 | 14% |
| Encoded payload | 1 | 5% |
| Composition risk | 0 | 0% |

The flagged skills and their finding counts:

| Skill | Findings | Max Severity | What It Does |
|-------|----------|-------------|--------------|
| anti-injection-skill | 9 | CRITICAL | Prompt injection defense |
| askhuman | 3 | CRITICAL | Human-in-the-loop API |
| curl-http | 3 | CRITICAL | HTTP request utility |
| didit-age-estimation | 3 | CRITICAL | Age verification API |
| claw-daily | 2 | CRITICAL | Daily challenge game |
| azure-devops | 1 | HIGH | Azure DevOps integration |
| relationships | 1 | HIGH | Social API client |

Data exfiltration dominated because the scanner flags outbound HTTP requests with credentials or data — and many legitimate skills make outbound HTTP requests because that's their entire purpose.

## Deep Dive: The Most Interesting Findings

### 1. The Security Skill That Flagged Itself

The most-flagged skill in the entire dataset was `anti-injection-skill` — a prompt injection defense tool. It triggered 9 findings across 4 categories.

Why? Because it contains examples of the attacks it defends against:

```markdown
# From anti-injection-skill's detection rules (line 7):
"ignore previous instructions"

# From its blocked command patterns (line 117):
"curl | bash, wget | sh"
"base64 -d | sh, eval, exec"

# From its output sanitization rules (lines 347-350):
"reveal your system prompt"
"print your instructions"
"output your system prompt"
```

The scanner correctly identified these patterns. Each one IS a prompt injection pattern, a privilege escalation pattern, or a prompt leaking pattern. But the skill isn't executing these attacks — it's listing them as patterns to *block*. The scanner can't tell the difference because it's doing pattern matching, not semantic analysis.

This is the most honest result in the entire scan. It demonstrates exactly what static analysis can and can't do. A scanner that finds `ignore previous instructions` in a skill file has done its job. Whether that string is an attack or a defense requires human judgment.

### 2. Legitimate API Skills Flagged for Data Exfiltration

Five skills were flagged for data exfiltration (EXFIL-001 through EXFIL-005) because they make HTTP POST requests to external APIs:

**askhuman** (3 findings) — This skill sends POST requests to `askhuman-api.onrender.com` to register for a human-in-the-loop challenge system. The scanner flagged:

```bash
curl -X POST https://askhuman-api.onrender.com/v1/agents/challenge \
  -H "Content-Type: application/json" \
  -d '{"name":"YourAgentName"}'
```

This is the skill's documented, intended behavior — registering with a challenge API. The scanner correctly identified an outbound POST with data. Whether this particular endpoint is trustworthy is a judgment call the scanner doesn't make.

**azure-devops** (1 finding) — Flagged for transmitting data to `dev.azure.com` using a personal access token (`${AZURE_DEVOPS_PAT}`). This is exactly what an Azure DevOps integration skill should do. But from a pure pattern-matching perspective, a skill sending credentials to an external URL is worth flagging.

**curl-http** (3 findings) — This is a curl cheat-sheet skill. It contains example commands like `curl https://api.example.com`. The scanner flagged the examples themselves. Technically correct — the skill does contain outbound HTTP patterns. Practically, these are documentation examples, not executable attacks.

### 3. Skills That Legitimately Need Review

Two skills stood out as genuinely worth human review:

**claw-daily** — This competition skill registers your agent with a third-party service (`daily.ratemyclaw.xyz`), stores an API key locally at `~/.config/claw-daily/credentials.json`, and sends submissions to a leaderboard. Every step is documented and intentional. But the pattern — register with unknown service, store credential, send data repeatedly — is exactly what a sophisticated exfiltration skill would look like. Whether you trust this depends on whether you trust the service operator.

**didit-age-estimation** — Sends facial images to a third-party API (`verification.didit.me`) for age estimation. The data being transmitted (face images) is significantly more sensitive than typical API payloads. The scanner flagged the outbound POST; the sensitivity of the payload is something a human reviewer would catch that the scanner won't.

## The False Positive Problem

14 of 22 findings (64%) were data exfiltration flags. Most were triggered by skills doing exactly what they were designed to do — calling external APIs. This is the fundamental tension in agent skill scanning:

**Any skill that calls an external API will trigger exfiltration rules.** And many useful skills exist specifically to call external APIs.

The scanner's job isn't to eliminate false positives — it's to surface patterns worth reviewing. An 18% flagging rate (7 of 40 skills) means a human reviewer can inspect every flagged skill in minutes. That's the value proposition: not "these skills are malicious," but "these 7 skills do things you should look at before trusting them with your agent's credentials."

## What This Means for Agent Developers

**1. Most skills are clean.** 82% of the skills we scanned had zero findings. The agent skill ecosystem isn't uniformly dangerous.

**2. The dangerous patterns cluster around data flow.** When skills do flag, it's overwhelmingly about outbound data transmission. If you're evaluating a skill, the first question to ask is: does this skill send data to external services, and do I trust those services?

**3. Security tools can be security risks.** The highest-flagged skill was a security defense tool. If your agent installs a "prompt injection defense" skill, that skill may need broader permissions and contain more sensitive patterns than a simple utility. Scan your security tools too.

**4. Pattern matching has clear limits.** Static analysis catches what it can see — string patterns in code blocks and markdown. It can't distinguish between a skill that documents `ignore previous instructions` as an attack to block versus a skill that uses it as an attack to execute. Behavioral analysis (sandboxing, runtime monitoring) is needed for that layer.

## How to Scan Your Own Skills

```bash
pip install agent-skill-scanner

# Scan a directory of skill files
agent-skill-scan scan --path ./skills/

# JSON output for CI integration
agent-skill-scan scan --path ./skills/ --output json

# Filter by severity
agent-skill-scan scan --path ./skills/ --min-severity HIGH
```

The scanner works on OpenClaw SKILL.md files and any markdown/YAML file with skill-format frontmatter. It runs 22 rules across 5 categories. Results include the specific rule, severity, matched evidence, and line number for every finding.

Also available as a [GitHub Action](https://github.com/rexcoleman/agent-skill-scan-action) for CI pipelines and as an [MCP server](https://github.com/rexcoleman/agent-skill-scan-mcp) for use directly in Claude Code.

## Methodology and Limitations

**What the scanner does:** Pattern-based static analysis against 22 YAML-defined rules. Rules were derived from OWASP LLM Top 10, InjecAgent taxonomy, ToolHijacker attack vectors, and software supply chain security patterns. Rules were built from first principles — not from inspecting the skills being scanned.

**What the scanner doesn't do:** Semantic analysis, LLM-powered reasoning, behavioral analysis, or runtime monitoring. It can't determine intent. It can't distinguish between a skill that contains `curl -X POST` as documentation versus as an attack payload. It reports patterns; humans interpret them.

**Dataset limitations:** 40 skills is a sample, not a census. These were curated from public repositories — they may not represent the full distribution of skills in the wild. The scanner also doesn't currently parse MCP server tool definitions (TypeScript format), which limits coverage of that ecosystem.

**False positive rate:** 64% of findings were in the data exfiltration category, most triggered by legitimate API usage. This is expected behavior for a pattern-based scanner and is consistent with the known limitation that static analysis over-flags outbound network calls. The scanner is designed to surface patterns for review, not to make trust decisions.

---
title: "State of AI Agent Security Q1 2026: 820 Malicious Skills, $500M in VC, and Zero Dedicated Tooling"
date: 2026-03-19
draft: false
tags: ["agent-security", "market-analysis", "signal-intelligence", "ai-security", "research-report"]
format: "research-report"
audience_side: "of-ai"
image_count: 0
description: "Systematic analysis of the AI agent security landscape: 820+ malicious skills on ClawHub, 30 MCP CVEs in 60 days, $500M+ VC funding, 29% enterprise readiness, and the gap between threat velocity and defense tooling."
---

## Abstract

The AI agent economy is expanding rapidly. Over 100 million developers and builders are now deploying autonomous agents that browse the web, execute code, manage files, and interact with external APIs. Security has not kept pace. This report presents a systematic signal analysis of the AI agent security landscape as of Q1 2026, synthesizing threat intelligence, market data, and community pain signals from across the ecosystem. The findings are stark: 820+ malicious skills have been identified on ClawHub (approximately 20% of the registry), 30 MCP-related CVEs were disclosed in a 60-day window, and VirusTotal remains blind to 6,487 agent-specific malicious tools. On the market side, over $500 million in venture capital has been deployed into agent security startups in Q1 2026 alone, yet only 29% of enterprises report having agent security policies in place. The gap between threat velocity and defense tooling represents both the central risk and the defining market opportunity in AI security today. This report documents the evidence, maps the competitive landscape, and identifies the specific defense categories where no dominant solution exists.

## 1. Introduction

We are in the first year of mass agent deployment, and the security posture is effectively zero.

AI agents — autonomous software systems that reason, plan, and act on behalf of users — have moved from research curiosity to production infrastructure in under 18 months. Frameworks like OpenClaw have crossed 117,000 GitHub stars [1]. Claude Code, Moltbot, and competing agent frameworks are being used to manage codebases, execute business workflows, monitor markets, and run 24/7 autonomous operations. The agent economy is projected to reach $8 trillion by 2030 [2].

But agents are not applications. They are not containers. They are not microservices. An agent has access to its host's file system, network, credentials, and reasoning process. A compromised agent is not a compromised browser tab — it is a compromised employee with the keys to everything. And unlike a compromised employee, a compromised agent operates at machine speed, executing 144 heartbeat cycles per day, each one an opportunity for data exfiltration, behavior modification, or lateral movement.

The security industry has not caught up. Traditional tools — antivirus, EDR, SAST, DAST — were designed for applications that execute deterministic code. Agents execute probabilistic reasoning chains over untrusted inputs. The attack surface is fundamentally different: prompt injection manipulates reasoning, malicious skills provide persistent execution access, and memory poisoning corrupts the agent's decision-making across sessions.

This report synthesizes threat signals, market signals, and community pain signals into a single landscape view. It draws on disclosed CVEs, vendor reports, community forums, VC filings, and original signal intelligence collection. The goal is not to predict the future of agent security, but to document its present with enough specificity that builders, defenders, and investors can make informed decisions about where the gaps are and what to build next.

## 2. Methodology

### Signal Intelligence System

This report is produced using a structured signal intelligence methodology designed for continuous market and threat monitoring. Five signal types are collected and scored:

1. **Pain signals** — evidence that a specific security problem is causing real harm to real users. Sources: Reddit threads, Hacker News discussions, GitHub issues, DEV.to posts, security incident disclosures. Scored on frequency (how often the pain is mentioned) and intensity (how severe the consequences are).

2. **Solution gap signals** — evidence that users want a solution that does not exist or that existing solutions are inadequate. Sources: "I wish there was..." statements, feature requests on security tools, comparisons between what exists and what's needed.

3. **Willingness-to-pay (WTP) signals** — evidence that buyers are spending or prepared to spend money on agent security. Sources: VC funding announcements, enterprise budget surveys, pricing pages, acquisition activity.

4. **Usage signals** — evidence of adoption patterns that create or reduce security exposure. Sources: GitHub star counts, download metrics, deployment surveys, framework adoption data.

5. **Champion signals** — evidence of specific individuals or organizations driving agent security practices. Sources: blog authors, open-source maintainers, conference speakers, security researchers publishing agent-specific work.

### Sources

Primary sources for this report include: Cisco State of AI Security 2026 Report [3], OWASP Top 10 for Agentic Applications [4], AgentSeal MCP server scan results [5], VirusTotal agent malware analysis [6], Check Point Research Claude Code CVE disclosures [7], TechCrunch and SiliconANGLE VC funding coverage [8][9][10], Help Net Security enterprise readiness survey [11], and community discussions across Hacker News (5 high-signal threads), DEV.to, and security vendor blogs. A full reference list is provided at the end of this report.

### Scoring

Pain points are ranked by a composite score: frequency (1-10) multiplied by intensity (1-5), producing a maximum score of 50. This ranking drives prioritization of both the threat analysis and the market gap analysis that follow.

## 3. Threat Landscape

### 3.1 Malicious Skills: 820+ on ClawHub

The most acute threat in the agent ecosystem is the supply chain compromise of skill marketplaces. ClawHub, the primary registry for OpenClaw skills, contains over 820 malicious skills — approximately 20% of the entire registry [6][12]. The Koi Security research team identified the "ClawHavoc" campaign alone as responsible for 341 malicious skills [6].

Malicious skills fall into three operational categories based on disclosed attack patterns:

**Data exfiltration skills** present as helpful utilities — "memory optimizer," "context analyzer," "performance monitor" — while scanning for API keys, OAuth tokens, and credentials on every heartbeat cycle. They use the agent's own web browsing capabilities to transmit stolen data, making the network traffic indistinguishable from normal agent operations.

**Behavior modification skills** do not steal data. They alter how the agent reasons by injecting hidden instructions into memory files, biasing tool selection, or modifying the agent's personality and goals. The agent continues to function, but its outputs are subtly corrupted — a particularly dangerous pattern for agents used in financial analysis, security monitoring, or business decision-making.

**Lateral movement skills** use the compromised agent as a platform to attack other systems. If the agent can send emails, the skill sends phishing emails. If the agent can execute code, the skill installs backdoors. If the agent interacts with other agents, the skill propagates. This is the traditional malware lateral movement pattern adapted for agent architecture [13].

The architectural reason skills are more dangerous than prompt injection is persistence. A prompt injection attack is bounded to a single conversation or context window — seconds of exposure. A malicious skill executes on every heartbeat cycle. With a 10-minute heartbeat, that is 144 executions per day, each with full access to the agent's context, memory, credentials, and capabilities [13]. The skill is not a drive-by attack. It is a persistent implant.

### 3.2 Framework Vulnerabilities: 30 MCP CVEs in 60 Days

The Model Context Protocol (MCP), the standard interface through which agents connect to external tools and data sources, has proven to be a rich vulnerability surface. In a 60-day window in early 2026, 30 CVEs were disclosed across the MCP ecosystem [14]. AgentSeal's scan of 1,808 MCP servers found that 66% had security findings, with 492 servers operating with no authentication or encryption whatsoever [5].

Key CVEs illustrate the severity:

- **CVE-2026-25253** — the first confirmed remote code execution (RCE) vulnerability in an agent framework. A crafted request to an OpenClaw instance could achieve full code execution on the host [15].
- **CVE-2025-59536 and CVE-2026-21852** — discovered by Check Point Research, these Claude Code vulnerabilities enabled RCE and API token exfiltration through project configuration files. A malicious repository containing a crafted CLAUDE.md file could compromise any developer who cloned it [7].
- **ClawJacked (CVE-2026-XXXX)** — a WebSocket/origin bypass attack where a crafted web page could silently hijack a developer's local agent via malicious JavaScript targeting local gateway endpoints, achieving one-click RCE [16][17].

The pattern is consistent: agent frameworks expose local endpoints, trust configuration files implicitly, and grant agents broad system access by default. Each of these architectural choices creates a vulnerability class, not just a single bug. Patching individual CVEs does not address the structural exposure.

### 3.3 Detection Gap: VirusTotal Blind to 6,487 Agent Tools

Traditional security scanning infrastructure cannot see agent-specific threats. VirusTotal's analysis of the ClawHub ecosystem found 6,487 agent tools that evade all detection engines [6]. These tools are not flagged as malicious because they do not match any signature in VirusTotal's database. They use legitimate agent APIs in combinations that produce malicious outcomes — clean code that creates harmful behavior.

This is the antivirus-to-EDR gap replaying in a new domain. Pattern-matching (static analysis, signature detection) catches obvious malicious code. Behavioral detection — watching what the tool actually does at runtime — catches the sophisticated attacks. The agent security ecosystem has static analysis tools (Cisco skill-scanner [18], Snyk agent-scan [19], Tencent AI-Infra-Guard [20], Pantheon MEDUSA [21]). It does not have a widely adopted behavioral detection system.

The 6,487 figure represents a known floor, not a ceiling. It counts only tools that have been submitted to VirusTotal for analysis. The actual number of undetectable malicious agent tools in the wild is likely higher.

### 3.4 Attack Surface Comparison

Three primary attack vectors define the agent threat landscape, each with distinct characteristics:

| Vector | Exposure Window | Persistence | Detection Difficulty | Current Defenses |
|--------|----------------|-------------|---------------------|-----------------|
| Prompt injection | Single context window (seconds) | None — ends when context closes | Medium — guardrails catch ~27% [4] | Guardrails, input filtering, oversight models |
| Malicious skills | Every heartbeat cycle (persistent) | Days to weeks until removal | High — clean code, malicious behavior | Static scanners (partial), manual audit |
| Memory poisoning | Cross-session (persists in memory files) | Weeks to months — survives restarts | Very high — silent behavioral change | Version control on memory (manual) |

Prompt injection receives the most attention in the security community, but malicious skills and memory poisoning represent higher-impact threats due to their persistence and detection difficulty. OWASP's finding that 73% of agent deployments are vulnerable to prompt injection [4] is concerning, but the 20% malicious skill rate on ClawHub is arguably a more immediate operational risk for any builder installing third-party tools.

## 4. Market Landscape

### 4.1 VC Investment: $500M+ in Agent Security

Venture capital has flooded into agent security in Q1 2026, with over $500 million deployed across four major rounds:

- **Armadin** — $190 million, founded by Kevin Mandia (Mandiant founder). Targeting autonomous agent security for enterprise. Pre-product at time of funding [8].
- **Kai Cyber** — $125 million. Building an agent-driven AI security platform [9].
- **7AI** — $166 million. AI security platform with broad scope [10].
- **Onyx Security** — $40 million. AI agent security platform, launched alongside the funding round [22].

Additionally, **OpenAI acquired Promptfoo**, the agent testing and security startup, validating the market through acqui-hire [23]. This is the first major exit in the agent security space.

The investment pattern signals strong conviction from institutional investors that enterprise agent security spend is coming. But it also reveals a gap: most of these startups are pre-product or very early stage. Armadin, the largest raise, was pre-product at the time of its $190 million round. The money has arrived before the products. The market is being created, not captured.

### 4.2 Enterprise Readiness: 29%

Enterprise preparedness for agent security is alarmingly low. Only 29% of organizations report having security policies specifically addressing agentic AI [11]. Meanwhile, 48% of security professionals identify AI agents as the number one emerging attack vector [11], and 80% of IT professionals report that agents have performed unauthorized actions in their environments [24].

The readiness gap is quantified further by budget data: 88% of senior executives report increasing AI budgets due to agentic AI delivering business value [11]. Enterprise security budgets are increasing 20-40% specifically for agent security add-ons [3]. Safety concerns dominate enterprise AI priorities at 23.6%, the highest single concern category [3]. The spend is coming. The tooling to absorb that spend is not ready.

Compliance add-ons for agent deployments are emerging as a standard budget line item: $5,000-$25,000 per deployment for GDPR/HIPAA/SOC2 compliance, and $3,200-$13,000 per month for operational security monitoring [3]. OWASP's Agentic Top 10, published in late 2025 [4], provides the compliance framework that enterprises will measure agent deployments against — creating a natural hook for any security product mapped to its categories.

### 4.3 Competitive Analysis

The agent security competitive landscape as of Q1 2026 divides into four tiers:

**Tier 1: Enterprise platforms (shipped, well-funded)**
- Cisco AI Defense / skill-scanner [18] — enterprise-weight skill scanning with LLM-based semantic analysis. Open-source component available.
- Snyk agent-scan [19] — MCP and skill vulnerability scanning, leveraging Snyk's existing developer security distribution.
- CyberArk, Palo Alto Networks — shipping agent security features within existing enterprise platforms [25][4].

**Tier 2: Funded startups (pre-product or early)**
- Armadin, Kai, 7AI, Onyx — combined $521 million in funding, all early stage. Targeting enterprise.

**Tier 3: Open-source tools (shipped, community-driven)**
- Tencent AI-Infra-Guard [20] — full-stack agent scanning, but Chinese-origin creates enterprise trust barriers.
- Pantheon MEDUSA [21] — 4,000+ rules, 76 analyzers. Strong static analysis.
- NanoClaw [26] — container isolation for agents (20,000 stars, 100,000+ downloads). Solves isolation, not monitoring.
- SkillVet (oakencore) — bash and grep based skill scanning. Functional but primitive.
- SkillFortify — formal verification for agent skills. Show HN stage.

**Tier 4: Research and SaaS (niche)**
- AgentSeal [5] — MCP server scanning. Has the data on server vulnerability rates.
- PointGuard AI — AI security incident monitoring.
- Lasso Security — prompt injection detection.

### 4.4 Runtime Monitoring Gap

The most significant gap in the competitive landscape is **runtime behavioral monitoring for agents**. Every tier above focuses on pre-deployment scanning (static analysis, vulnerability detection, configuration auditing) or isolation (container sandboxing). None provides real-time monitoring of what an agent is actually doing during execution.

NanoClaw solves the isolation problem — running agents in containers to limit blast radius. But it does not monitor or alert on behavior within the container [26]. Cisco and Snyk scan skills before installation, but do not watch skill behavior at runtime. MEDUSA and AI-Infra-Guard perform static analysis, not dynamic observation.

The 80% statistic — IT professionals reporting agents performing unauthorized actions [24] — points directly at this gap. Organizations know their agents are misbehaving. They have no tooling to detect when it happens, what specifically the agent did, or how to enforce behavioral policies in real-time.

This is the EDR-equivalent problem for agents: traditional antivirus (static scanning) is necessary but insufficient. The market needs behavioral detection and response — watching what agents actually do, comparing it against policy, and alerting or blocking when behavior deviates. No company dominates this category. The category barely exists.

## 5. Pain Signal Analysis

### 5.1 Top 10 Pain Points Ranked by Frequency x Intensity

The following pain point ranking is derived from community signal mining across Hacker News, GitHub, security vendor blogs, DEV.to, and security research publications. Each pain point is scored on frequency (how often it appears in community discussion, 1-10) and intensity (how severe the consequences are, 1-5).

| Rank | Pain Point | Score | Category |
|------|-----------|-------|----------|
| 1 | Malicious skills in agent marketplaces (820+ on ClawHub) | 45 | Supply chain |
| 2 | Prompt injection enabling RCE and data exfiltration (73% vulnerable) | 45 | Prompt injection |
| 3 | Credential exposure in agent configs (plaintext API keys, OAuth tokens) | 40 | Credential exposure |
| 4 | MCP server vulnerabilities (30 CVEs in 60 days, 66% with findings) | 32 | Skill security |
| 5 | Agent memory poisoning / persistence (cross-session, nearly undetectable) | 30 | Memory corruption |
| 6 | Unrestricted system access by default (no least-privilege enforcement) | 28 | Deployment hardening |
| 7 | WebSocket/origin bypass enabling remote takeover (ClawJacked: 1-click RCE) | 25 | Skill security |
| 8 | No standardized agent security compliance framework | 24 | Compliance |
| 9 | Clone-and-pwn repository attacks (malicious CLAUDE.md / hooks / MCP configs) | 20 | Data exfiltration |
| 10 | VirusTotal cannot detect agent-specific malware (6,487 tools undetectable) | 20 | Supply chain |

The top two pain points are tied at 45, but their character is different. Malicious skills are a supply chain problem with a known, quantifiable scope (820+ skills, 20% of registry). Prompt injection is a model-layer problem with no complete solution. Both are critical, but supply chain attacks are more tractable — they can be addressed with better scanning, behavioral analysis, and marketplace governance.

### 5.2 Willingness-to-Pay Signals

WTP signals segment cleanly across three buyer categories:

**Segment C (Enterprise):** The strongest WTP signals. $500M+ in VC deployed on the bet that enterprises will pay. Enterprise security budgets increasing 20-40% for agent security [3]. $5K-$25K compliance add-ons per agent deployment. $3.2K-$13K/month operational security monitoring as a standard line item. 88% of senior executives increasing AI budgets [11]. Safety concerns are the top enterprise priority at 23.6% [3].

**Segment B (Small-to-mid security teams):** The beachhead market. These teams feel the pain — malicious skills, credential exposure, unauthorized agent actions — but cannot afford enterprise pricing from Cisco or Snyk. Estimated WTP: $100-$2,000/month for agent security tooling. This segment is underserved: too large for free open-source tools, too small for enterprise sales cycles.

**Segment A (Solo developers):** Near-zero WTP. Solo builders use free tools — SkillVet is bash and grep with zero dependencies. This segment is a funnel for brand awareness and community distribution, not a revenue source. The correct model is freemium: free tier for solo developers, paid for teams.

### 5.3 Champion Signals

Seven individuals and organizations have emerged as active champions in the agent security space, each producing high-signal work:

- **oakencore** (SkillVet author) — built the most widely used open-source skill scanner. Understands the pain firsthand.
- **qwibitai** (NanoClaw creator) — built the leading security-focused OpenClaw alternative. 20,000 stars, 100,000+ downloads. Already running a business on agent security.
- **bazzz** (DEV.to) — built a 6-pass security scanner after identifying 824 malicious ClawHub skills [27].
- **AgentSeal team** — scanned 1,808 MCP servers, published the 66% findings rate. Primary source of MCP server security data [5].
- **Koi Security** — discovered the ClawHavoc campaign (341 malicious skills). Threat intelligence source [6].
- **Check Point Research** — discovered CVE-2025-59536 and CVE-2026-21852. Deep Claude Code security expertise [7].
- **SkillFortify author** — building formal verification for agent skills. Approaching the problem from a different angle than behavioral analysis.

These champions represent the practitioner community building agent security from the ground up. Their work, limitations, and gaps are direct inputs to product strategy for anyone building in this space.

## 6. Implications

### For Builders Deploying Agents

The immediate action is to eliminate third-party skills or replace them with locally-built versions you control. The 20% malicious rate on ClawHub means installing a random skill is roughly equivalent to running unverified code from the internet — something no developer would do with a Python package but many do with agent skills because the risk model has not been communicated.

Beyond skills: lock down agent network exposure, version-control memory directories, implement oversight loops (a cheap local model auditing a worker agent), and assume every website your agent browses is an untrusted input. A practical hardening checklist can be completed in 30 minutes and meaningfully reduces the attack surface [28].

### For Defenders and Security Teams

The agent threat model is structurally different from the application threat model. Static analysis is necessary but insufficient. The 6,487 tools evading VirusTotal demonstrate that agents need behavioral detection — watching what tools and skills actually do at runtime, not just scanning their code. Security teams should be investing in runtime monitoring capabilities now, before agent deployments scale further.

OWASP's Agentic Top 10 [4] provides the first compliance framework for agent security. Security teams should map their agent deployments against it and identify which categories they have coverage for and which they do not.

### For the Industry

The $500M+ in Q1 2026 VC funding validates market demand. But the distribution of that funding — concentrated in pre-product enterprise startups — means the actual tooling gap will persist for 12-18 months while these companies build and ship. The open-source community (NanoClaw, MEDUSA, skill-scanner, AI-Infra-Guard) is shipping faster than the funded startups.

The biggest structural gap is runtime behavioral monitoring. The industry has scanning (Cisco, Snyk, Tencent, MEDUSA), isolation (NanoClaw), and compliance frameworks (OWASP). It does not have a widely adopted system for watching what agents do and enforcing behavioral policies in real-time. This is the EDR moment for agent security.

## 7. Limitations

This report has several important limitations that readers should consider when interpreting the findings.

**Community signal bias.** Pain point rankings are derived from public community discussion on Hacker News, GitHub, DEV.to, and vendor blogs. These sources over-represent English-speaking, developer-centric perspectives and under-represent enterprise security teams, non-English markets, and organizations that do not discuss security issues publicly.

**Snapshot in time.** The agent security landscape is evolving weekly. CVE counts, malicious skill counts, and competitive positions will change. This report reflects data as of mid-March 2026.

**No proprietary data.** All data in this report is drawn from public sources. Enterprise security posture data comes from vendor surveys (Cisco, Help Net Security, CyberArk) with their associated sampling biases. Actual enterprise agent security practices may differ from survey responses.

**Malicious skill counting methodology.** The 820+ figure aggregates community reporting, ClawHub registry analysis, and vendor disclosures (including the Koi Security ClawHavoc campaign). Independent verification of every malicious skill has not been performed. ClawHub's internal moderation and detection rates are not publicly documented.

**WTP extrapolation.** Willingness-to-pay signals are inferred from VC funding, enterprise budget surveys, and pricing data. They are indicators of market direction, not confirmed purchase commitments.

## 8. Conclusion

The AI agent security landscape in Q1 2026 is defined by a single structural fact: threat velocity has outpaced defense tooling by at least an order of magnitude. 820+ malicious skills represent 20% of ClawHub's registry. 30 MCP CVEs were disclosed in 60 days. VirusTotal cannot see 6,487 agent-specific malicious tools. Only 29% of enterprises have agent security policies. These are not projections — they are current measurements.

The market response is beginning: $500M+ in VC, enterprise budgets increasing 20-40%, OWASP compliance frameworks published. But the tooling lags the funding. Most well-funded startups are pre-product. The open-source community is shipping faster. And the most critical gap — runtime behavioral monitoring — has no dominant player at any tier.

For builders, defenders, and investors, the implication is the same: the window to define agent security practices is open now. The patterns established in the next 12 months will determine whether the agent economy develops with security built in, or repeats the retrofit cycle that has defined every previous generation of computing infrastructure.

## References

[1] "117,000 Developers Starred a Security Nightmare," Medium, 2026.
[2] ARK Invest, "Big Ideas 2026," ARK Investment Management, 2026.
[3] Cisco, "State of AI Security 2026 Report," Cisco Blogs, 2026.
[4] OWASP, "Top 10 for Agentic Applications 2026," GenAI OWASP, 2026.
[5] AgentSeal, "66% of MCP Servers Had Findings," agentseal.org, 2026.
[6] VirusTotal, "From Automation to Infection: How OpenClaw Skills Are Weaponized," VirusTotal Blog, February 2026.
[7] Check Point Research, "RCE and API Token Exfiltration through Claude Code Project Files (CVE-2025-59536)," 2026.
[8] TechCrunch, "Mandiant's founder just raised $190M for his autonomous AI agent security startup," March 2026.
[9] SiliconANGLE, "Cybersecurity startup Kai raises $125M to build agent-driven AI security platform," March 2026.
[10] 7AI funding coverage, multiple sources, Q1 2026.
[11] Help Net Security, "Enterprises racing to secure agentic AI," February 2026.
[12] Socket, "OpenClaw Skill Marketplace Emerges as Active Malware Vector," Socket Blog, 2026.
[13] R. Coleman, "Why Third-Party Skills Are the Biggest Agent Attack Vector," rexcoleman.dev, March 2026.
[14] "MCP Security 2026: 30 CVEs in 60 Days," heyuan110.com, March 2026.
[15] The Hacker News, "OpenClaw AI Agent Flaws Could Enable RCE," March 2026.
[16] The Hacker News, "ClawJacked Flaw Lets Malicious Sites Hijack Agents," February 2026.
[17] Oasis Security, "ClawJacked: OpenClaw Vulnerability," oasis.security, 2026.
[18] Cisco AI Defense, "skill-scanner," GitHub, 2026.
[19] Snyk, "agent-scan," GitHub, 2026.
[20] Tencent, "AI-Infra-Guard," GitHub, 2026.
[21] Pantheon Security, "MEDUSA," GitHub, 2026.
[22] IndexBox, "Onyx Security launches AI security platform after $40M funding round," 2026.
[23] TechBuzz AI, "OpenAI acquires Promptfoo to secure AI agent ecosystem," 2026.
[24] Cisco, "Personal AI agents like OpenClaw are a security nightmare," Cisco Blogs, 2026.
[25] CyberArk, "What's Shaping the AI Agent Security Market in 2026," CyberArk Blog, 2026.
[26] NanoClaw, GitHub repository and VentureBeat coverage, 2026.
[27] bazzz, "I built a 6-pass security scanner for OpenClaw skills after 824 malicious ones were found on ClawHub," DEV.to, 2026.
[28] R. Coleman, "How to Secure Your OpenClaw in 30 Minutes," rexcoleman.dev, March 2026.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

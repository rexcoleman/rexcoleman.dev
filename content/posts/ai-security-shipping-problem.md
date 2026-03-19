---
title: "AI Security Has a Shipping Problem"
date: 2026-03-19
draft: false
tags: ["ai-security", "industry-analysis", "singularity-cybersecurity", "agent-security"]
format: "perspective"
audience_side: "both"
image_count: 0
description: "The AI security industry produces frameworks and guidelines but almost no one ships working tools that practitioners can deploy today."
author: "Rex Coleman"
ShowToc: true
TocOpen: true
---

**Thesis:** The AI security industry produces frameworks and guidelines but almost no one ships working tools that practitioners can deploy today.

The gap between "risk identified" and "risk mitigated" in AI security is wider than any other area of cybersecurity I've worked in. We have more frameworks per deployed tool than any domain in the history of information security. And the frameworks keep coming while the tools don't.

## The Evidence

**1. OWASP published the Agentic Top 10 in late 2025. No tools enforce it.**

OWASP's Agentic Security Initiative identified 10 risk categories (ASI-01 through ASI-10) for autonomous AI agents. It's well-researched. It defines real risks. And as of March 2026, there is no open-source tool that tests for even one of these 10 categories. When I built [agent-redteam-framework](https://github.com/rexcoleman/agent-redteam-framework), I mapped 19 attack scenarios to 7 of the 10 OWASP categories. It was the first executable implementation I could find. That's not a brag — it's an indictment of the field. A framework published four months ago should have dozens of testing tools by now.

**2. 820+ malicious skills on ClawHub, and VirusTotal can't detect them.**

One in five skills on ClawHub — the largest agent skill marketplace — is actively malicious. These skills exfiltrate data, modify agent behavior, and enable lateral movement. Traditional security scanners, including VirusTotal, miss 6,487 malicious agent tools because they look for file-level signatures, not behavioral patterns. The detection gap is architectural: agent-specific malware doesn't look like traditional malware because it operates through legitimate agent APIs. We identified the threat. We quantified it. We haven't shipped the scanner.

**3. $500M+ in VC funding, but buyers report 29% readiness.**

In Q1 2026 alone, Armadin raised $190M, Kai raised $125M, 7AI raised $166M, and Onyx raised $40M — all in the agent security space. The money says the market is real. But enterprise surveys show only 29% of organizations feel prepared to secure agentic AI. Meanwhile, 48% of security professionals say agents are their #1 attack vector. Half a billion dollars in and the buyer readiness needle hasn't moved. The capital is flowing to platforms and dashboards, not to the practitioners who need to secure agents this week.

**4. NIST AI RMF exists. govML is the only open-source implementation I can find.**

NIST published the AI Risk Management Framework. ISO published 42001. The EU AI Act created compliance requirements. When I searched for open-source tools that implement these frameworks as executable governance — templates you can drop into a project, generators that enforce compliance automatically, phase gates that catch violations before they ship — I found almost nothing. So I built [govML](https://github.com/rexcoleman/govML): 50+ templates, 20+ generators, 10 profiles. After 14 manual audit cycles on my own ML projects (with 30+ findings each), I learned that governance-as-prose doesn't work. Governance-as-code does. But the industry is still publishing prose.

**5. 30 MCP server CVEs in 60 days. 66% of servers have security findings.**

The MCP (Model Context Protocol) ecosystem accumulated 30 CVEs in its first 60 days. A scan of 1,808 MCP servers found that 66% had security findings, and 492 had no authentication or encryption at all. This is the agent equivalent of discovering that two-thirds of web servers are running without HTTPS — except it took the web a decade to get there, and MCP reached that state in two months. The vulnerability reports are published. The remediation tooling doesn't exist.

## What This Means for the Field

AI security is following a pattern I've seen before in cybersecurity: the advisory class moves faster than the engineering class. Frameworks proliferate because they're cheaper to produce than tools. A working paper costs weeks. A working tool costs months. But the frameworks without tools create a dangerous illusion of progress. CISOs can point to "OWASP alignment" in a board deck while their agents run 820 unscanned skills.

The consequence is a credibility gap. Security practitioners — the people who actually have to defend these systems — are losing trust in the advisory layer because the advice doesn't come with implementation. "Validate all agent inputs" is correct advice. How? With what tool? Against what baseline?

Every framework that ships without a reference implementation is a promise the industry hasn't kept.

## What I'm Doing About It

I started [Singularity Cybersecurity](https://singularitycyber.com) because I got tired of the gap between research and deployment. The thesis is simple: AI security research should ship.

That means every finding produces a tool, not just a paper. When I found that [adversarial control analysis](/posts/adversarial-control-analysis/) predicts which features attackers exploit, I shipped the methodology as reusable code across six domains. When I found that [RL agents have attack surfaces](/posts/rl-agent-vulnerability/) that prompt-injection defenses miss entirely, I shipped the attack framework with executable scenarios. When I found that third-party skills are the biggest agent attack vector, I started building SkillVet [HYPOTHESIZED] (behavioral sandbox scanning) and AgentArmor [HYPOTHESIZED] (runtime monitoring).

The bar should be: did you ship something a practitioner can use this week? If the answer is no, you wrote a framework. The industry has enough frameworks.

### Limitations

The 29% enterprise readiness figure comes from industry surveys with self-reported data. The $500M+ VC figure represents disclosed rounds in Q1 2026 and likely undercounts total investment. "No tools enforce OWASP Agentic Top 10" reflects my search as of March 2026 — tools may exist that I haven't found. The govML claim (only open-source NIST AI RMF implementation) is based on GitHub search and may miss private or differently-named implementations.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

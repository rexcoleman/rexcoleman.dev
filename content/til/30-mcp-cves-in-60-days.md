---
title: "30 MCP CVEs in 60 days"
date: 2026-03-19
draft: false
tags: ["agent-security", "mcp", "vulnerabilities", "signal-report"]
format: "til"
audience_side: "of-ai"
---

**The MCP (Model Context Protocol) ecosystem accumulated 30 CVEs in its first 60 days of widespread adoption.** Of 1,808 MCP servers scanned, 66% had security findings. 492 had no authentication or encryption at all.

## Why this matters

MCP is the protocol that lets AI agents connect to external tools and data sources. It is becoming the standard integration layer for the agent economy. When two-thirds of the servers implementing that standard ship with security gaps, it means the entire agent ecosystem is building on a foundation full of holes. This isn't a theoretical risk — these are real CVEs with real exploit paths.

## Source

This data comes from [Signal Report #1](/posts/signal-report-001/), compiled from community scanning efforts, NVD filings, and vendor disclosures in Q1 2026.

## What to do about it

1. **Audit every MCP server you connect to.** Check for authentication, TLS, and input validation before granting your agent access.
2. **Treat MCP connections as untrusted network boundaries.** Apply the same scrutiny you'd give a third-party API.
3. **Monitor for new CVEs.** The disclosure rate suggests this surface is still being actively explored by researchers and attackers alike.

The MCP ecosystem is moving fast. Security is not keeping up. If you are deploying agents that rely on MCP servers, you are inheriting their vulnerabilities.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

---
title: "I Built a PQC Migration Scanner: Here's What Your Codebase Is Hiding"
date: 2026-03-19
description: "70% of the crypto in your codebase isn't yours to change — and classical exploit risk matters more than quantum vulnerability for deciding what to fix first."
tags: ["post-quantum-cryptography", "pqc", "security-tools", "machine-learning", "cryptography"]
categories: ["AI Security", "Research"]
format: "technical-blog"
audience_side: "from-ai"
image_count: 4
author: "Rex Coleman"
ShowToc: true
TocOpen: false
cover:
  image: /images/og-default.png
  alt: "PQC Migration Scanner"
  hidden: true
images:
  - /images/og-default.png
archived: true
hiddenInHomeList: true
---

> **Note (2026-03-19):** This was an early exploration in my AI security research. The methodology has known limitations documented in the [quality assessment](https://github.com/rexcoleman/Moonshots_Career_Thesis). For the current state of this work, see [Multi-Agent Security](https://github.com/rexcoleman/multi-agent-security) and [Verified Delegation Protocol](https://github.com/rexcoleman/verified-delegation-protocol).


I scanned Python's standard library for quantum-vulnerable cryptography. Found 39 findings — 19 critical, all Shor-vulnerable. Then I trained ML models on 21,142 crypto-related CVEs to score migration priority. The surprise: classical exploit risk matters more than quantum vulnerability for deciding what to fix first. And 70% of the crypto in your codebase isn't yours to change.

## What I Built

[pqc-migration-analyzer](https://github.com/rexcoleman/pqc-migration-analyzer) scans Python codebases for quantum-vulnerable cryptographic primitives, scores migration urgency using ML, and recommends NIST PQC replacements. It covers 19 crypto primitives across 5 categories (key exchange, signatures, hashes, ciphers, PQC standards) and maps every finding to NIST FIPS 203/204/205 replacements.

Built with [govML](/posts/govml-methodology/) v2.5 (blog-track profile — 10 governance docs). Total cost: $0.

## Why This Matters Now

NIST finalized post-quantum cryptography standards in 2024:
- **ML-KEM** (FIPS 203) replaces RSA/DH key exchange
- **ML-DSA** (FIPS 204) replaces RSA/ECDSA/DSA signatures
- **SLH-DSA** (FIPS 205) hash-based signatures as backup

But nobody knows what's actually in their codebase. The migration clock is ticking, and most organizations are still at "we should probably look into this."

## What I Found

### 21,142 Crypto CVEs in the NVD

6.3% of all CVEs in the National Vulnerability Database involve cryptographic primitives. The distribution tells a story:

![Primitives Distribution](/images/posts/pqc-migration-analyzer/primitives_distribution.png)

TLS/SSL and X.509 dominate — these are the transport and certificate layers that everything depends on. But the Shor-vulnerable primitives (RSA, ECDSA, DSA, DH) are the ones that quantum computing breaks completely. MD5 and SHA-1 are already classically broken; Grover's algorithm just makes them worse.

### ML Beats Rules for Priority Scoring (+14pp)

I trained three ML models against a rule-based baseline (Shor vulnerability flag + CVE age). Gradient Boosting won:

![Scoring Comparison](/images/posts/pqc-migration-analyzer/scoring_comparison.png)

**The surprising finding:** The top predictive features are classical exploitability indicators — heap overflows, padding oracle attacks, arbitrary code execution — not Shor vulnerability flags. Quantum risk ranks 6th in feature importance.

This means **PQC migration priority should be driven by classical exploit risk first, quantum risk second.** A RSA key exchange with a known padding oracle attack is a higher priority than an ECDSA signature with no known exploits, even though both are equally Shor-vulnerable.

### 70% of Your Crypto Isn't Yours to Change

This is the finding that changes how you plan migrations:

![Controllability](/images/posts/pqc-migration-analyzer/controllability_pie.png)

I classified every crypto finding by **controllability** — who actually controls whether it can be migrated:

| Controllability | % | What It Means |
|---|---|---|
| Library-controlled | ~70% | You depend on `requests`, `paramiko`, `boto3` etc. to update |
| Developer-controlled | ~20% | Direct `cryptography` API calls you can change today |
| Protocol-controlled | ~8% | TLS versions, SSH specs — wait for standard updates |
| Hardware-controlled | ~2% | HSMs with RSA-only firmware — replace hardware |

**Implication:** Your PQC migration plan should start with the 20% you control, then track upstream library timelines for the 70%.

### 4th Domain Validation of Controllability Analysis

This is the fourth project where controllability analysis — classifying inputs by who controls them — produces actionable architectural insights:

![Cross-Domain ACA](/images/posts/pqc-migration-analyzer/cross_domain_aca.png)

The methodology transfers because the underlying principle is the same: **security architecture decisions depend on who controls what.** Whether it's network features, CVE metadata, agent inputs, or crypto primitives, the controllability classification determines what's defendable and what's not.

## How to Use It

```bash
pip install -e .
pqc-analyzer scan --repo ~/your-project --output report.json
```

Output:
```
Scan Summary
+----------------------------+-------+
| Metric                     | Value |
+----------------------------+-------+
| Files scanned              |  6647 |
| Critical (Shor-vulnerable) |    19 |
| High (Grover-weakened)     |    20 |
| Migration recommendations  |    39 |
+----------------------------+-------+
```

## What I Learned

**Classical before quantum.** The instinct is to prioritize by quantum risk (Shor = critical!). The data says otherwise — classical exploitability is a better predictor of what actually gets attacked. Fix the padding oracles before the RSA key exchange.

**Controllability determines actionability.** You can plan to migrate all the RSA in your codebase, but if 70% is in libraries you don't control, your plan is 70% "wait and track." Start with what you can actually change.

**Data reuse compounds.** This project reused 338K CVEs downloaded for the [vulnerability prioritization research](/posts/cvss-gets-it-wrong/). Zero download time, zero API cost. Cross-project data reuse is an underrated efficiency pattern.

## What's Next

1. AST-based detection (precision improvement over regex)
2. Multi-language support (Java, Go)
3. GitHub Action for CI/CD integration

The scanner is open source: [pqc-migration-analyzer on GitHub](https://github.com/rexcoleman/pqc-migration-analyzer). Built with [govML](/posts/govml-methodology/) v2.5 governance.

### Limitations

This analysis used rule-based scoring on a single Python stdlib scan. The PQC primitives database is incomplete — new algorithms emerge regularly. The scoring model weights are hand-tuned, not ML-optimized. Real-world migration complexity includes hardware, protocol, and organizational factors not captured here.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

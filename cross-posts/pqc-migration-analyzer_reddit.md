# I Built a PQC Migration Scanner: Here's What Your Codebase Is Hiding

Scanned Python's standard library for quantum-vulnerable cryptography. 39 findings — 19 critical, all Shor-vulnerable. Then trained ML models on 21,142 crypto-related CVEs to score migration priority.

**The surprise: classical exploit risk matters more than quantum vulnerability for deciding what to fix first.**

Gradient Boosting beat the rule-based baseline (Shor flag + CVE age) by +14pp. The top predictive features are classical exploitability indicators — heap overflows, padding oracle attacks, arbitrary code execution. Quantum risk (Shor vulnerability flag) ranks 6th in feature importance. A RSA key exchange with a known padding oracle is higher priority than an ECDSA signature with no known exploits, even though both are equally Shor-vulnerable.

**70% of your crypto isn't yours to change.** I classified every finding by controllability:
- Library-controlled (~70%): depends on requests, paramiko, boto3 to update
- Developer-controlled (~20%): direct cryptography API calls you can change today
- Protocol-controlled (~8%): TLS versions, SSH specs — wait for standards
- Hardware-controlled (~2%): HSMs with RSA-only firmware

Your PQC migration plan should start with the 20% you control, then track upstream library timelines for the 70%.

The scanner covers 19 crypto primitives across 5 categories (key exchange, signatures, hashes, ciphers, PQC standards) and maps every finding to NIST FIPS 203/204/205 replacements. This is the 4th domain where controllability analysis produces actionable architectural insights — same principle (classify inputs by who controls them) applied to cryptographic migration.

Data reuse: this project reused 338K CVEs downloaded for a previous vulnerability prioritization project. Zero download time, zero API cost.

Full write-up with code: https://rexcoleman.dev/posts/pqc-migration-analyzer/

Repo: https://github.com/rexcoleman/pqc-migration-analyzer

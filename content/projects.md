---
title: "Projects"
layout: "single"
ShowToc: false
ShowReadingTime: false
---

9 shipped projects at every layer of the stack. Every project ships FINDINGS.md with demonstrated results.

### Agent Security Red-Team Framework

Systematic red-teaming of autonomous AI agents. 7 attack classes (5 not in OWASP/MITRE), 19 scenarios, 100% success with reasoning chain hijacking against default-configured agents. Tested on LangChain + CrewAI. Cost: ~$2 in API tokens.

[GitHub](https://github.com/rexcoleman/agent-redteam-framework) · [Write-up](/posts/agent-redteam/)

---

### RL Agent Vulnerability Framework

RL-specific attacks on autonomous agents. 4 attack classes, 2 custom Gymnasium environments, 40 trained agents including transformer policy. Observation perturbation degrades agents 20-50x more than reward poisoning. OWASP Agentic 7/10 mapped.

[GitHub](https://github.com/rexcoleman/rl-agent-vulnerability) · [Write-up](/posts/rl-agent-vulnerability/)

---

### Model Behavioral Fingerprinting

Unsupervised backdoor detection for ML models. 6 anomaly detectors × 5 representations = 30-combination benchmark plus contrastive learning. Behavioral fingerprinting detects what static analysis misses.

[GitHub](https://github.com/rexcoleman/model-behavioral-fingerprint) · [Write-up](/posts/model-fingerprinting/)

---

### Adversarial ML on Network Intrusion Detection

Adversarial evaluation of ML-based IDS with adversarial control analysis. 57 attacker-controllable vs 14 defender-observable features. Feature controllability reduces attack success 35%.

[GitHub](https://github.com/rexcoleman/adversarial-ids-ml) · [Write-up](/posts/adversarial-ids/)

---

### ML-Powered Vulnerability Prioritization

Predicting real-world CVE exploitability. Trained on 338K CVEs. Outperforms CVSS by +24pp AUC. SHAP explainability reveals vendor history and CVE age matter more than severity score.

[GitHub](https://github.com/rexcoleman/vuln-prioritization-ml) · [Write-up](/posts/cvss-gets-it-wrong/)

---

### AI Supply Chain Security Scanner

Static analysis scanner for ML project dependencies. 20 findings across 5 real projects (13 CRITICAL). Detects unsafe deserialization, known CVEs in ML libraries, and supply chain risks.

[GitHub](https://github.com/rexcoleman/ai-supply-chain-scanner)

---

### Financial Anomaly Detection

Fraud detection with CFA-domain features. XGBoost AUC 0.987. CFA features capture 91% of ML signal. 81% adversary-resistant floor from system-controlled features.

[GitHub](https://github.com/rexcoleman/financial-anomaly-detection)

---

### PQC Migration Analyzer

Post-quantum cryptography migration tool. 21K crypto-related CVEs scanned. ML scorer adds +14pp vs baseline. 70% of vulnerable crypto is in dependencies, not your code.

[GitHub](https://github.com/rexcoleman/pqc-migration-analyzer)

---

### govML

Open-source governance framework for ML projects. 42 templates, 4 profiles, 19 generators. Contract-driven reproducibility used across all of the above. 469+ tests.

[GitHub](https://github.com/rexcoleman/govML) · [Write-up](/posts/govml-methodology/)

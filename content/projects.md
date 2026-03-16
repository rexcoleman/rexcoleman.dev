---
title: "Projects"
layout: "single"
ShowToc: false
ShowReadingTime: false
---

## govML

Open-source governance framework for ML projects — 39 templates, 4 profiles (including contract-track for CS 7641-level rigor), 8+ generators, leakage test automation. Contract-driven development with machine-checkable provenance. Used across 7 real projects.

**Stack:** Python, YAML, Bash · **Status:** Active (v2.6)

[GitHub](https://github.com/rexcoleman/govML) · [Write-up](/posts/govml-methodology/)

---

## ML-Powered Vulnerability Prioritization Engine

ML model predicting real-world CVE exploitability. Trained on 338K CVEs (NVD + ExploitDB + EPSS). Outperforms CVSS by +24pp AUC. SHAP explainability reveals vendor history and CVE age matter more than severity score. Adversarial evaluation: 0% evasion via adversarial control analysis.

**Stack:** Python, scikit-learn, XGBoost, SHAP · **Data:** 338K CVEs

[GitHub](https://github.com/rexcoleman/vuln-prioritization-ml-) · [Write-up](/posts/cvss-gets-it-wrong/)

---

## Adversarial ML on Network Intrusion Detection

Adversarial evaluation of ML-based IDS with adversarial control analysis. 57 attacker-controllable vs 14 defender-observable features. Constraint-aware detection achieves 100% detection rate on noise attacks. Feature controllability methodology validated as cross-domain principle.

**Stack:** Python, ART, scikit-learn · **Data:** CICIDS2017

[GitHub](https://github.com/rexcoleman/adversarial-ids-ml) · [Write-up](/posts/adversarial-ids/)

---

## Agent Security Red-Team Framework

Systematic red-teaming of autonomous AI agents. 7 attack classes (5 not in OWASP/MITRE), 19 scenarios, 100% success with reasoning chain hijacking against default-configured agents. Layered defense architecture with LLM-as-judge. Tested on LangChain + CrewAI.

**Stack:** Python, LangChain, LangGraph, CrewAI · **Cost:** ~$2 in API tokens

[GitHub](https://github.com/rexcoleman/agent-redteam-framework) · [Write-up](/posts/agent-redteam/)

---

## AI Supply Chain Security Scanner

Static analysis scanner for ML project dependencies. 20 findings across 5 real projects (13 CRITICAL). Detects unsafe deserialization (pickle.load), known CVEs in ML libraries, and supply chain risks. Rule-based — no ML, pure security engineering.

**Stack:** Python, AST analysis · **Domains:** 6th ACA domain

[GitHub](https://github.com/rexcoleman/ai-supply-chain-scanner)

---

## Financial Anomaly Detection (CFA-Informed)

Fraud detection on synthetic financial data with CFA-domain features. XGBoost AUC 0.987. CFA features capture 91% of ML signal. 81% adversary-resistant floor from system-controlled features. Controllability analysis validated for 5th domain.

**Stack:** Python, XGBoost, SHAP · **Data:** PaySim 100K transactions

[GitHub](https://github.com/rexcoleman/financial-anomaly-detection)

---

## PQC Migration Analyzer

Post-quantum cryptography migration tool. Scanned 21K crypto-related CVEs. ML scorer (+14pp vs baseline) for prioritizing migration. 70% of vulnerable crypto is in dependencies, not your code.

**Stack:** Python, scikit-learn · **Data:** NVD + NIST PQC standards

[GitHub](https://github.com/rexcoleman/pqc-migration-analyzer)

---
title: "Projects"
layout: "single"
ShowToc: false
ShowReadingTime: false
---

## govML

Reusable governance framework for ML projects — 32 templates, 7 quickstart profiles, 7 generators + agent orchestrator. From experiment design through publication. Enforces reproducibility, decision traceability, and quality gates.

**Stack:** Python, YAML, Bash · **Status:** Active (v2.4)

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

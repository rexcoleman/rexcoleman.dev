# Why CVSS Gets It Wrong: ML-Powered Vulnerability Prioritization

I trained ML models on 338,000 real CVEs from NVD, cross-referenced with 24,936 ExploitDB entries and 320,502 EPSS scores. Temporal split: train on pre-2024 CVEs, test on 2024+. 49 features engineered from practitioner knowledge.

**CVSS predicts exploitability with AUC 0.662 — barely better than random.** Logistic Regression achieves 0.903 (+24pp). EPSS (already ML-based) achieves 0.912.

The interesting question: what does the model see that CVSS doesn't?

SHAP feature importance reveals the answer. The #1 predictor is vendor CVE count — a proxy for deployment ubiquity. Attackers invest where the payoff is highest: a vulnerability in software deployed across millions of endpoints is worth weaponizing. #2 is CVE age — weaponization follows a lifecycle (disclosure to PoC to exploit kit to active exploitation) that takes months. #3 is description length — complex, multi-step vulnerabilities get longer descriptions and are exactly what threat actors invest in. CVSS score ranks #5.

I applied adversarial control analysis: classified features as attacker-controllable (15 features including description text, keywords) vs defender-observable (11 features including CVSS, CWE, EPSS, vendor history). Three attacks on description text achieved 0% evasion. The model is naturally robust because its top features are all outside attacker control. An attacker can rewrite a CVE description but can't change the vendor's CVE history, publication date, or EPSS score.

Practical takeaway: stop prioritizing by CVSS alone. If you're already using EPSS, you're ahead of most teams — our model achieves 99% of EPSS performance using only public data. The model is hard to game because advisory-level deception doesn't change predictions.

Limitation: ExploitDB labels for 2024+ CVEs are incomplete (0.3% test exploit rate). No proprietary threat intel data.

Full write-up with code: https://rexcoleman.dev/posts/cvss-gets-it-wrong/

Repo: https://github.com/rexcoleman/vuln-prioritization-ml-

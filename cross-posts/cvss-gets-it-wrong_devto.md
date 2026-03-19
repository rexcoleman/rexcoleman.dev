---
title: "Why CVSS Gets It Wrong: ML-Powered Vulnerability Prioritization"
published: true
canonical_url: "https://rexcoleman.dev/posts/cvss-gets-it-wrong/"
tags: [aisecurity, machinelearning, vulnerabilitymanagem, shap]
---

After years in cybersecurity watching security teams burn hours on the wrong vulnerabilities, I watched teams patching CVSS 9.8 vulnerabilities that never got exploited — while CVSS 7.5s got weaponized and led to breaches. CVSS measures severity. Attackers measure opportunity. I trained an ML model on 338,000 real CVEs to find out what actually predicts which vulnerabilities get exploited in the wild — and the answer is not what CVSS thinks it is.

## The Data

Three public data sources, joined by CVE ID:

| Source | Records | Purpose |
|--------|---------|---------|
| NVD (NIST) | 337,953 CVEs | Features: CVSS scores, CWE types, descriptions, vendor/product, references |
| ExploitDB | 24,936 CVEs with known exploits | Ground truth label: "was this CVE actually exploited?" |
| EPSS (First.org) | 320,502 scores | Baseline comparison: an existing ML-based prediction |

**Temporal split:** Train on pre-2024 CVEs (234,601), test on 2024+ (103,352). This prevents data leakage from future information — in production, you always predict on CVEs you haven't seen yet.

## 49 Features from Practitioner Knowledge

I engineered 49 features across six categories:

- **CVSS components** — base score, attack vector, complexity, privileges required
- **Temporal** — publication year, month, day-of-week, CVE age in days
- **Vendor metadata** — number of CVEs the vendor has (a proxy for deployment ubiquity)
- **CWE classification** — top 20 weakness types as one-hot features
- **References** — count, presence of exploit references, presence of patch references
- **Practitioner keywords** — 11 binary features encoding terms I know from Mandiant triage: `remote_code_execution`, `sql_injection`, `buffer_overflow`, `privilege_escalation`, `authentication_bypass`, `denial_of_service`, `xss`, `information_disclosure`, `arbitrary_code`, `allows_attackers`, `crafted`

The keyword features are the "practitioner vs formula" thesis made explicit. If these features rank high in SHAP importance, it validates that domain knowledge has signal CVSS doesn't capture.

## Results: ML Crushes CVSS (+24pp AUC)

| Model | AUC-ROC | vs CVSS |
|-------|---------|---------|
| **Logistic Regression** | **0.903** | **+24.1pp** |
| Random Forest | 0.864 | +20.2pp |
| XGBoost | 0.825 | +16.3pp |
| Best CVSS Threshold (≥9.0) | 0.662 | baseline |
| **EPSS (already ML-based)** | **0.912** | +25.1pp |

CVSS predicts exploitability with an AUC of 0.662 — barely better than random for a binary classifier. The simplest ML model (Logistic Regression) achieves 0.903. EPSS, which is already an ML model trained on richer data, achieves 0.912.

**The interesting question isn't "can ML beat CVSS?" — that's obvious. It's "what does the model see that CVSS doesn't?"**

## SHAP Reveals What Actually Predicts Exploitation

The top predictors of real-world exploitation, ranked by SHAP importance:

**#1: How many CVEs a vendor has (vendor_cve_count).** This is the single strongest predictor, and it's not what most people expect. Vendors with large CVE histories — Microsoft, Apache, Oracle, Linux kernel — get exploited disproportionately. Not because their code is worse, but because attackers invest where the payoff is highest. A vulnerability in software deployed across millions of endpoints is worth weaponizing; a vulnerability in a niche product isn't. From studying years of threat intelligence reporting, the pattern is consistent: threat actors maintain exploit toolkits for high-deployment-count vendors and add new CVEs to existing toolchains. The attacker's calculus is "how many targets does this give me access to?" — and vendor CVE count is a proxy for deployment ubiquity.

**#2: How old the CVE is (cve_age_days).** Weaponization is not instant. The vulnerability lifecycle follows a predictable arc: disclosure → proof-of-concept (days to weeks) → integration into exploit kits (weeks to months) → active exploitation in the wild (months to years). A CVE that's been public for 6 months without a known exploit is less urgent than one that's been public for 2 years with active weaponization. Age is a feature CVSS ignores entirely.

**#3: Description length.** Longer CVE descriptions correlate with exploitation because complex, multi-step vulnerabilities require more detailed documentation. A simple null pointer dereference gets a 2-sentence description. A chained vulnerability involving authentication bypass, privilege escalation, and remote code execution gets a paragraph — and is the kind of bug threat actors invest in weaponizing.

**#8: SQL injection keyword.** SQLi has been the single most reliably exploitable vulnerability class for two decades — well-understood, tooling is mature (sqlmap), and it provides direct data access.

**#12: Remote code execution keyword.** RCE is the ultimate attacker goal: arbitrary code execution means game over.

CVSS score? **#5.** The formula everyone uses for prioritization is the fifth most important feature. Vendor history, vulnerability age, and description complexity all matter more.

![SHAP feature importance — top 20 features driving exploitation prediction, with vendor CVE count and vulnerability age dominating over CVSS score](/images/posts/cvss-gets-it-wrong/shap_bar_top20_seed42.png)

## Adversarial Robustness: 0% Evasion

I applied the same [adversarial control analysis](/posts/adversarial-ids/) I developed for intrusion detection:

| Feature Category | Count | Examples |
|-----------------|-------|---------|
| **Attacker-controllable** | 15 | Description text, keywords, reference links |
| **Defender-observable only** | 11 | CVSS score, CWE, EPSS, publication date, vendor history |

Three attacks on the description text (synonym substitution, field injection, noise perturbation) achieved **0% evasion**. The model is naturally robust because its top features (vendor_cve_count, cve_age_days, cvss_score, epss_percentile) are all defender-observable. An attacker can rewrite the CVE description to hide an RCE, but they can't change the vendor's CVE history, the publication date, or the EPSS score.

**This validates the adversarial control analysis across a second domain.** The [first validation](/posts/adversarial-ids/) was on network intrusion detection (packet features). This is on vulnerability metadata (CVE features). Same principle, different domain: **design ML systems so decision-critical inputs are outside adversary control.**

## What This Means for Vulnerability Management

1. **Stop prioritizing by CVSS alone.** It's the 5th most important feature. Vendor deployment ubiquity and vulnerability age are stronger signals.
2. **EPSS mostly works.** Our model achieves 99% of EPSS performance using only public data. If you're already using EPSS, you're ahead of most teams.
3. **The model is hard to game.** Because it relies on features attackers can't manipulate, advisory-level deception (downplaying a CVE's description) doesn't change the prediction.

## Limitations

- **Ground truth lag:** ExploitDB labels for 2024+ CVEs are incomplete — many exploited vulns haven't been catalogued yet. Test exploit rate is only 0.3%.
- **No proprietary data:** EPSS has access to threat intelligence feeds and social media that we don't. Fair comparison on methodology, not data.
- **Single seed:** Results shown for seed=42. Multi-seed stability analysis is a follow-up.

## Code

Full pipeline (ingest → features → models → SHAP → adversarial eval) is open source:

[github.com/rexcoleman/vuln-prioritization-ml](https://github.com/rexcoleman/vuln-prioritization-ml)

Built with [govML](https://github.com/rexcoleman/govML) governance — 11 architectural decisions logged, every experiment reproducible.

### What's Next

The ablation study continues — I'm testing which data source combinations are sufficient vs redundant for vulnerability prediction. I also applied the same adversarial robustness methodology to network IDS: [Adversarial ML on IDS →](/posts/adversarial-ids/)

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

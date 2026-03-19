---
title: "A CFA Charterholder Built an ML Fraud Detector: Here's What the Models Miss"
date: 2026-03-19
description: "CFA-informed rule-based scoring achieves 0.898 AUC on its own, and 8 of the top 20 predictive features come from domain expertise, not raw data."
tags: ["machine-learning", "fraud-detection", "financial-ml", "adversarial-ml", "feature-engineering"]
format: "technical-blog"
audience_side: "from-ai"
image_count: 5
author: "Rex Coleman"
ShowToc: true
TocOpen: false
cover:
  image: /images/og-default.png
  alt: "A CFA Charterholder Built an ML Fraud Detector"
  hidden: true
images:
  - /images/og-default.png
---

I'm a CFA charterholder who builds ML systems. I trained XGBoost on 100K financial transactions to detect fraud — AUC 0.987. But the most interesting finding wasn't the model performance. It was that CFA-informed rule-based scoring achieves 0.898 AUC on its own, and 8 of the top 20 predictive features come from domain expertise, not raw data.

Here's what happens when you bring financial analysis training to ML fraud detection.

## Why CFA x ML Matters

Most ML fraud detection papers treat feature engineering as a purely statistical exercise: normalize amounts, encode categoricals, maybe add some velocity features. A CFA sees transactions differently:

- **Amount-to-median ratio** (not raw amount) — a $500 transaction at a gas station is suspicious; at a car dealer, it's normal
- **Merchant risk tiers** — not all merchants are equal; high-risk categories (online gaming, crypto exchanges) have higher fraud baselines
- **Suspicious timing** — night + weekend + high amount = different risk profile than Tuesday afternoon

These are features a domain expert engineers. A pure ML practitioner wouldn't think to create them. And SHAP shows they matter.

## Results

### ML Beats Rules, But Rules Are Strong

![Model Comparison](/images/posts/financial-anomaly-detection/model_comparison.png)

XGBoost achieves 0.987 AUC — excellent. But the CFA-informed rule-based baseline scores 0.898. That's not a weak baseline. It means **domain expertise in rules captures ~91% of what ML captures.** The last 9 percentage points come from non-linear interactions ML finds automatically.

### CFA Features in Top 20 SHAP

![SHAP Feature Importance](/images/posts/financial-anomaly-detection/shap_summary.png)

8 of the top 20 most predictive features are CFA-informed:
1. **amt_to_median_ratio** (rank 4) — relative transaction size vs merchant normal
2. **protonmail** (rank 5) — privacy-focused email = risk signal
3. **high_risk_country** (rank 10)
4. **suspicious_time** (rank 15) — night + weekend

The raw `TransactionAmt` ranks 7th. The CFA-informed `amt_to_median_ratio` ranks 4th. Relativizing amounts to merchant context adds predictive power.

### Controllability: The 81% Adversary-Resistant Floor

![Controllability](/images/posts/financial-anomaly-detection/controllability.png)

Applying controllability analysis (5th domain validation):

| Features | Controllability | AUC |
|---|---|---|
| All 18 features | Mixed | 0.987 |
| System-only (6 features) | Adversary-resistant | **0.798** |

A sophisticated fraudster controls: transaction amount, timing, email, billing country. They do NOT control: card BIN, device fingerprint, merchant risk score, address verification result. The system-only model retains 81% of detection capability even if the fraudster perfectly manipulates everything they control.

### 5 Domains, 1 Methodology

![Cross-Domain ACA](/images/posts/financial-anomaly-detection/cross_domain_5.png)

This is the fifth project where controllability analysis produces actionable security insights. The pattern holds across network security, vulnerability prediction, AI agents, cryptographic migration, and now financial fraud. It's a general principle.

### Complexity Curves: Shallow Trees Win

![Complexity Curves](/images/posts/financial-anomaly-detection/complexity_curves.png)

XGBoost peaks at max_depth=2 (AUC 0.990) and degrades with deeper trees. LightGBM is more robust to over-parameterization. SVM-RBF shows the steepest overfitting. The lesson: on this data, simplicity beats capacity.

## What I Learned

**Rules aren't dead.** The ML community often dismisses rule-based systems. In fraud detection, CFA-informed rules provide a strong floor (0.898 AUC) that ML improves upon but doesn't replace. The optimal system uses both: rules as the fast path, ML for edge cases.

**Domain expertise is a feature engineering multiplier.** The same raw data produces better features when engineered by someone who understands the domain. CFA training teaches you to think in ratios, risk tiers, and temporal patterns — exactly what fraud ML needs.

**Controllability quantifies adversarial robustness.** Instead of asking "can a fraudster evade the model?" ask "what's the detection floor from features the fraudster can't control?" The answer (81%) is the number a CISO needs.

The code is open source: [financial-anomaly-detection on GitHub](https://github.com/rexcoleman/financial-anomaly-detection). Built with [govML](https://github.com/rexcoleman/govML) v2.5.

### Limitations

This analysis uses synthetic transaction data (PaySim), which simulates but doesn't perfectly replicate real-world fraud patterns. The CFA-informed rules were designed by a single analyst — different domain experts might identify different features. All models were evaluated on a single temporal split without rolling-window validation. The controllability analysis classifies features qualitatively — a more rigorous approach would quantify controller influence.

### What's Next

I'm extending the adversarial controllability analysis to more domains — see [One Principle, Six Domains](/posts/adversarial-control-analysis/) for the cross-domain methodology. The feature engineering approach here (domain expertise → feature design → ML validation) is a template I'm applying to every new security domain. The financial fraud application validates that ACA works outside network security.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

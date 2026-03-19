# A CFA Charterholder Built an ML Fraud Detector: Here's What the Models Miss

I'm a CFA charterholder who builds ML systems. Trained XGBoost on 100K financial transactions to detect fraud — AUC 0.987. But the most interesting finding wasn't model performance.

**CFA-informed rule-based scoring achieves 0.898 AUC on its own.** That means domain expertise in rules captures ~91% of what ML captures. The last 9 percentage points come from non-linear interactions ML finds automatically.

**8 of the top 20 SHAP features are CFA-informed:**
- amt_to_median_ratio (rank 4) — relative transaction size vs merchant normal
- protonmail flag (rank 5) — privacy-focused email as risk signal
- high_risk_country (rank 10)
- suspicious_time (rank 15) — night + weekend pattern

The raw TransactionAmt ranks 7th. The CFA-informed amt_to_median_ratio ranks 4th. Relativizing amounts to merchant context adds predictive power. These are features a domain expert engineers. A pure ML practitioner wouldn't think to create them.

**Controllability analysis (5th domain validation):** A sophisticated fraudster controls transaction amount, timing, email, billing country. They do NOT control card BIN, device fingerprint, merchant risk score, address verification result. The system-only model (6 features, all adversary-resistant) retains 81% of detection capability — 0.798 AUC even if the fraudster perfectly manipulates everything they control.

**Complexity curves:** XGBoost peaks at max_depth=2 (AUC 0.990) and degrades with deeper trees. LightGBM is more robust to over-parameterization. SVM-RBF shows steepest overfitting. Simplicity beats capacity on this data.

Rules aren't dead. The optimal fraud detection system uses both: rules as the fast path, ML for edge cases. And controllability quantifies the adversarial robustness number a CISO actually needs.

Full write-up with code: https://rexcoleman.dev/posts/financial-anomaly-detection/

Repo: https://github.com/rexcoleman/financial-anomaly-detection

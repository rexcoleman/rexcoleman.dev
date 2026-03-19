# One Principle, Six Domains: Adversarial Control Analysis for AI Security

I applied the same security principle across 6 different domains. Every time, the finding was the same: the inputs the attacker can't touch are your real defense.

**Adversarial Control Analysis (ACA)** has three steps: enumerate all inputs, classify each by controller (attacker-controlled, defender-observable, system-determined), build defenses around the boundary.

**Results across 6 domains:**

1. **Network IDS:** 57 of 78 features attacker-controllable, 14 defender-observable. Constraining attacks to controllable features only, detection holds at 100% for noise methods. Unconstrained attacks achieve up to 38% evasion.

2. **Vulnerability Prediction:** ML beats CVSS by +24pp AUC. Top SHAP feature is EPSS percentile — a real-time signal attackers can't manipulate. Three adversarial attacks on description text achieved 0% evasion.

3. **AI Agents:** Attack success correlates inversely with defender observability. Reasoning chain (internal, invisible) = 100% attack success. User prompts (visible, filterable) = 80%. Tool outputs (partially observable) = 25%.

4. **PQC Migration:** 70% of quantum-vulnerable crypto lives in libraries you depend on. Classical exploit risk matters more than quantum risk for prioritization. Start with the 20% you control.

5. **Financial Fraud:** System-only features (card BIN, device fingerprint, merchant risk score) retain 81% of full model detection. Fraudsters can't manipulate these regardless of how sophisticated they are.

6. **AI Supply Chain:** Defenders control the deserialization pipeline (which formats to accept, which loaders to use). Attackers control model files. 75% of critical findings are developer-fixable.

The principle works because security is fundamentally about asymmetric control. Most ML security research treats all features as equally perturbable. ACA maps the control boundary and focuses defenses where they survive adversarial pressure.

Full write-up: https://rexcoleman.dev/posts/adversarial-control-analysis/

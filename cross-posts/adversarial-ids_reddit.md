# Adversarial ML on Network Intrusion Detection: What Adversarial Control Analysis Reveals

I built and red-teamed an ML-based intrusion detection system. Trained Random Forest, XGBoost, and Logistic Regression on CICIDS2017 (2.83M network flow records, 78 features, 15 traffic classes) with 5-seed averaging.

Before designing attacks, I classified every feature by who controls it — something most adversarial ML papers skip. The split: 57 attacker-controllable features (payload bytes, packet count, flag counts) vs 14 defender-observable features (flow duration, inter-arrival time, TCP window size).

**The key finding:** When attacks are constrained to only modify attacker-controllable features (the realistic scenario), constraint-aware detection using defender-observable features achieves 100% detection rate on noise attacks.

Under unconstrained attacks (the typical academic threat model where the attacker perturbs everything), evasion climbed to 38% against Logistic Regression and 12% against XGBoost. Under constrained attacks with only attacker-controllable features: 0% evasion. The gap between those two numbers is the gap between theoretical and realistic adversarial risk.

This is an architectural defense, not a model defense. It doesn't matter whether you use Random Forest or a neural network. What matters is that your system's decision depends on inputs outside adversary control. A concrete example: `fwd_pkt_len_mean` (mean forward packet length) is attacker-controllable — the attacker decides how much data to stuff into each packet. But `flow_iat_mean` (mean inter-arrival time) depends on network hop count, congestion, and router queuing delays. The attacker can't dictate traversal time across three autonomous systems.

I call this adversarial control analysis (ACA). I've since validated it on vulnerability prediction (0% evasion — top features are all outside attacker control), AI agents (attack success correlates inversely with defender observability), PQC migration, financial fraud detection, and AI supply chain security. Same principle across 6 domains.

The 57/14 split isn't in any dataset description or ML framework. It comes from understanding how TCP/IP works and how real attackers operate. SHAP tells you which features matter; only a practitioner tells you which features an attacker controls.

Full write-up with code: https://rexcoleman.dev/posts/adversarial-ids/

Repo: https://github.com/rexcoleman/adversarial-ids-ml

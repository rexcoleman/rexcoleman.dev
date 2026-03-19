# Antivirus for AI Models: Behavioral Fingerprinting Detects What Static Analysis Misses

How do you detect a backdoored ML model when the weights look normal and static analysis finds nothing? Same way we solved malware detection: behavioral analysis. I built a system that fingerprints model behavior using unsupervised anomaly detection.

The pipeline: feed the model curated reference inputs, extract activation patterns from intermediate layers, build a baseline from known-clean models, flag deviations. No labeled backdoor examples needed. No model retraining.

**150 experiments:** 6 anomaly detectors (Isolation Forest, One-Class SVM, GMM, Autoencoder, PCA+Mahalanobis, LOF) x 5 feature representations (Raw, PCA, ICA, Random Projection, SimCLR) x 5 seeds. 200 synthetic model fingerprints per seed (160 clean, 40 test with 8 backdoored).

Results: Local Outlier Factor on raw features achieves best mean AUROC 0.622. Best single run: One-Class SVM + PCA at 0.770. Every detector exceeds random chance.

**The surprise: raw features beat dimensionality reduction.** I expected PCA or ICA to help. The opposite happened (Raw 0.607 vs PCA 0.578 vs ICA 0.568). The backdoor signal is diffuse — tiny perturbations spread across many dimensions. PCA concentrates variance in top components dominated by normal variation. DR throws away exactly the subtle information you need.

SimCLR contrastive learning failed completely (AUROC 0.466, below chance). No natural augmentation structure for model fingerprints — random noise augmentation doesn't preserve semantic relationships between clean fingerprints.

The controllability advantage: the defender controls the probe inputs. The attacker must create a model that behaves normally on whatever reference inputs the defender chooses while activating its backdoor only on specific triggers. And the attacker must fool all 6 detectors simultaneously. The fundamental asymmetry favors defenders.

Honest limitation: synthetic data, not real backdoored models (BadNets, WaNet). Real-model validation on TrojAI benchmarks is next.

Full write-up with code: https://rexcoleman.dev/posts/model-fingerprinting/

Repo: https://github.com/rexcoleman/model-behavioral-fingerprint

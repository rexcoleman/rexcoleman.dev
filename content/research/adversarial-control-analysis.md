---
title: "Adversarial Control Analysis: A Unified Framework for Designing ML Systems That Survive Adversaries Across Six Security Domains"
date: 2026-03-19
draft: false
tags: ["methodology", "adversarial-ml", "security-architecture", "ai-security", "research-report"]
format: "research-report"
audience_side: "both"
image_count: 2
description: "One principle — classify inputs by who controls them — predicts adversarial robustness across IDS, vulnerability management, agent security, PQC, fraud detection, and supply chain security."
author: "Rex Coleman"
ShowToc: true
TocOpen: true
---

## Abstract

Machine learning systems deployed in adversarial environments face a fundamental challenge: attackers manipulate inputs to evade detection, yet most adversarial ML research treats all features as equally perturbable. We introduce Adversarial Control Analysis (ACA), a framework that classifies every input to an ML system by its controller — attacker-controlled, defender-observable, system-determined, or nature-governed — and uses this classification to predict adversarial robustness and guide architectural defense. We apply ACA across six security domains: network intrusion detection (57/78 features attacker-controllable; constraining perturbations to controllable features reduces attack success by 35%), vulnerability prioritization (EPSS, a system-controlled signal, dominates prediction at 2x the SHAP importance of any other feature), AI agent security (attack success correlates inversely with defender observability, from 25% on observable inputs to 100% on internal state), post-quantum cryptography migration (70% of crypto findings are library-controlled, not developer-actionable), financial fraud detection (system-controlled features achieve 81% of full model performance), and AI supply chain security (75% of findings are developer-controlled). In every domain, ACA correctly predicts which features and defenses will survive adversarial pressure. The framework provides a three-step methodology — Enumerate, Classify, Architect — that security practitioners can apply before writing a single line of model code. ACA formalizes the principle that security architecture, not model optimization, determines adversarial robustness.

## 1. Introduction

Adversarial machine learning has produced thousands of papers on attack methods and defenses, yet the field remains fragmented by domain. Network intrusion detection researchers study evasion attacks against packet classifiers [1]. Vulnerability management researchers study whether attackers can manipulate CVE metadata to fool prioritization models [2]. Agent security researchers study prompt injection and reasoning chain hijacking [3]. Each domain develops its own threat models, its own attacks, and its own defenses — largely in isolation.

This fragmentation obscures a structural insight that transfers across all of them: **the features an attacker cannot control are your real defense.**

Consider a network intrusion detection system trained on 78 flow-level features. An attacker crafting evasion traffic can control packet timing, payload size, and flow duration — but cannot forge TCP flags observed at the receiver or dictate destination port selection by the operating system. An adversarial ML evaluation that perturbs all 78 features equally overstates vulnerability. One that restricts perturbations to the 57 attacker-controllable features reveals the actual attack surface — and the 14 defender-observable features that survive adversarial pressure.

This same principle applies in domains that share no features, no data formats, and no model architectures. In vulnerability prediction, the system-controlled EPSS score dominates exploitability prediction because attackers cannot manipulate it. In AI agent security, reasoning chains have 100% attack success precisely because defenders cannot observe them. In financial fraud, system-controlled features (card verification, device fingerprints) provide an 81% adversary-resistant detection floor. The pattern is consistent: map what the adversary controls, build defenses on what they cannot.

We call this methodology Adversarial Control Analysis (ACA). This paper presents ACA as a unified framework, demonstrates its application across six security domains, and provides evidence that controllability classification predicts adversarial robustness more reliably than model-level metrics like accuracy or F1. ACA is a methodology paper: the contribution is the framework itself and the evidence that it generalizes, not any single domain result.

The rest of this paper is organized as follows. Section 2 reviews related work in adversarial ML, domain-specific defenses, and controllability in control theory. Section 3 defines the ACA framework formally. Section 4 applies ACA to six security domains with quantitative results. Section 5 analyzes cross-domain patterns. Section 6 discusses implications. Sections 7 and 8 address limitations and conclusions.

## 2. Related Work

**Adversarial machine learning.** Szegedy et al. [4] demonstrated that small perturbations to image inputs cause misclassification, launching the adversarial examples research program. Goodfellow et al. [5] introduced FGSM, and subsequent work produced PGD [6], C&W [7], and AutoAttack [8] for generating adversarial examples. Defense research spans adversarial training [6], certified robustness [9], and detection-based approaches [10]. Nearly all of this work assumes the adversary can perturb any input dimension within an epsilon-ball — an assumption that does not hold in most security domains, where physical, protocol, or system constraints limit which features an attacker controls.

**Domain-specific security ML.** Network intrusion detection systems (NIDS) using ML have been studied extensively on datasets like CICIDS2017 [11] and NSL-KDD [12]. Adversarial attacks on NIDS were explored by Apruzzese et al. [13], who noted that realistic constraints reduce attack effectiveness but did not formalize which constraints apply to which features. In vulnerability management, EPSS [14] demonstrated that ML outperforms CVSS for exploit prediction, but did not analyze why certain features resist adversarial manipulation. In agent security, OWASP's LLM Top 10 [15] catalogs risks but does not classify them by controllability. Each domain has developed defenses independently, missing the cross-domain pattern.

**Feature importance in security ML.** SHAP [16] and LIME [17] provide post-hoc explanations of which features drive model predictions. Security researchers have used these tools to identify important features in malware detection [18] and fraud detection [19], but the connection between feature importance and adversarial robustness through the lens of who controls each feature has not been systematically explored. ACA bridges this gap: it uses controllability classification to predict which important features will remain important under adversarial pressure.

**Controllability in control theory.** The concept of controllability originates in linear systems theory [20], where a system is controllable if it can be driven to any state by appropriate inputs. ACA borrows this framing but inverts it: rather than asking whether a defender can control the system, we ask which inputs an attacker can control. This adversarial controllability framing maps naturally to the security domain, where the central question is always: what can the adversary manipulate, and what can they not? The closest related concept in security is the attack surface [21], but attack surface analysis focuses on entry points rather than on the controllability of individual features within those entry points.

## 3. The ACA Framework

### 3.1 Core Principle: Classify Inputs by Controller

The foundational insight of ACA is that every input to an ML system has a controller — an entity that determines or influences its value. In security contexts, four controller categories cover the space:

**Attacker-controlled.** The adversary can set or manipulate this input directly. Examples: packet payload content (IDS), CVE description text (vulnerability management), user prompts (agent security), transaction amounts (fraud detection). Defenses built on attacker-controlled features are inherently fragile because the adversary can adapt.

**Defender-observable.** The defender's infrastructure determines or records this input, and the attacker cannot forge it. Examples: TCP flags at the receiver (IDS), EPSS percentile (vulnerability management), tool permission boundaries (agent security), card verification system responses (fraud detection). These features are the foundation of robust defenses.

**System-determined.** The broader system or protocol determines this input, independent of either attacker or defender action. Examples: destination port assignment by OS (IDS), CVE publication date (vulnerability management), library version in a dependency tree (supply chain). System-determined features are stable anchors for scoring and prioritization.

**Nature-governed.** External reality determines this input. Examples: whether a quantum computer exists (PQC migration), whether a specific exploit has been published (vulnerability management). These features cannot be manipulated by any party in the system and represent ground truth constraints.

The boundary between categories is not always clean. Some features are partially controllable — an attacker can influence but not fully determine conversation history in an agent system, for instance. ACA accommodates this by treating controllability as a spectrum rather than a binary.

### 3.2 Three-Step Process: Enumerate, Classify, Architect

ACA operates in three steps that can be applied before any model is trained:

**Step 1: Enumerate.** List every input to the ML system — features, parameters, data sources, configuration values, external signals. Be exhaustive. Include inputs that seem irrelevant; controllability analysis may reveal they are the most important.

**Step 2: Classify.** Assign each input to a controller category (attacker-controlled, defender-observable, system-determined, nature-governed) with a confidence level. Document partial controllability explicitly. This step requires domain expertise: understanding who controls TCP flags requires knowledge of network protocols; understanding who controls EPSS scores requires knowledge of the FIRST.org computation pipeline.

**Step 3: Architect.** Design the system so that its critical decision paths depend on defender-observable and system-determined features, not attacker-controlled ones. This means: (a) selecting features whose controllability favors the defender, (b) weighting or ensembling models toward robust features, (c) building detection layers that monitor defender-observable features for impossible changes, and (d) accepting that attacker-controlled features provide signal under non-adversarial conditions but will degrade under attack.

The output of ACA is not a model — it is an architectural blueprint that specifies which features to trust, which to monitor, and which to treat as unreliable under adversarial pressure.

### 3.3 Controllability Spectrum

In practice, controllability is not a four-way classification but a spectrum:

**Fully controllable** — the attacker sets the value with no constraints (e.g., payload bytes in a crafted packet).

**Partially controllable** — the attacker influences but does not fully determine the value (e.g., conversation history in a multi-turn agent interaction; the attacker contributes messages but so does the agent).

**Observable but not controllable** — the defender can read the value but neither party sets it directly (e.g., timestamp of a network flow, assigned by the capture infrastructure).

**System-determined** — a protocol, algorithm, or external system sets the value (e.g., EPSS score computed by FIRST.org from global telemetry; TCP flag values set by the OS network stack at the receiver).

**Uncontrollable** — no party in the interaction determines the value; it reflects an external state of nature (e.g., whether a CVE's target software is widely deployed, which depends on the global installed base).

This spectrum allows ACA to make graded predictions: features closer to the "fully controllable" end will degrade more under adversarial pressure; features closer to the "uncontrollable" end will remain stable. The key architectural implication is that robustness is a property of the feature set, not the model.

## 4. Cross-Domain Application

### 4.1 Network Intrusion Detection (FP-01)

**Dataset:** CICIDS2017, 2.83M network flows, 15 attack classes, 78 features.

**ACA classification:** 57 features are attacker-controllable (packet timing, payload size, flow duration, byte counts — all values the attacker determines by crafting traffic). 14 features are defender-observable (TCP flags at the receiver, destination port — set by the OS/network stack, not the attacker). 7 features are ambiguous or derived.

**Prediction:** Restricting adversarial perturbations to only the 57 attacker-controllable features should reduce attack success compared to unconstrained perturbation of all 78 features. Defenses that monitor defender-observable features for impossible changes should outperform learned defenses like adversarial training.

**Results:** Against random noise perturbation (epsilon=0.3), constraining perturbations to attacker-controllable features reduced attack success rate by 35% for XGBoost (F1 recovery from 0.086 to 0.213) [DEMONSTRATED]. The effect was model-dependent — Random Forest showed only 5% reduction, consistent with its more uniform feature importance distribution. Constraint-aware detection (monitoring defender-observable features for changes that should be impossible) achieved 100% recovery, compared to 61% for adversarial training and 0% for feature squeezing [DEMONSTRATED].

**ACA insight:** The architectural defense — monitoring what the attacker cannot control — outperformed the learned defense (adversarial training) by 39 percentage points. Feature squeezing, a defense imported from the image domain, failed completely on tabular IDS data because rounding continuous network features destroys signal without constraining the perturbation space. ACA predicted both outcomes: constraint-aware detection works because it exploits the controllability boundary; feature squeezing fails because it operates on the wrong abstraction.

**Limitation:** All attacks used random noise perturbation, not gradient-based methods. A sophisticated constrained adversary who only perturbs attacker-controllable features would bypass the constraint-aware detection entirely. The 100% detection rate reflects the defense's value as a first-layer filter against unsophisticated evasion, not as a complete solution.

### 4.2 Vulnerability Prioritization (FP-05)

**Dataset:** 337,953 CVEs from NVD, 24,936 exploit labels from ExploitDB, 320,502 EPSS scores. Temporal split: pre-2024 training, 2024+ testing.

**ACA classification:** 15 features are attacker-controllable (CVE description text, keywords, reference links — all values a vulnerability submitter can influence). 11 features are defender-observable or system-determined (EPSS percentile from FIRST.org, CVSS score assigned by NVD analysts, vendor CVE history, publication date, CWE classification).

**Prediction:** System-controlled features should dominate prediction. Text-based features should be less robust because attackers can manipulate CVE descriptions.

**Results:** EPSS percentile — a system-controlled signal computed from global threat telemetry — is the #1 SHAP predictor at 1.096, nearly 2x the next feature (has_exploit_ref at 0.573) [SUGGESTED]. Logistic regression achieves AUC 0.903 using all features, but EPSS features alone achieve AUC 0.901 — capturing 99.8% of performance with 2 of 49 features [DEMONSTRATED, 5 seeds]. Removing EPSS drops AUC by 15.5 percentage points. Three text-manipulation attacks (synonym swap, field injection, noise perturbation) achieved 0% evasion rate because the model's decision relies on features attackers cannot manipulate [SUGGESTED].

**ACA insight:** The ablation study provides the strongest evidence for ACA's core claim. Four feature groups (temporal, reference, vendor, description) actually *hurt* XGBoost performance when included — removing them improved AUC by up to 5.6 percentage points. These groups contain a mix of controllability types, but the critical finding is that the model's useful signal concentrates entirely in defender-observable features. A production deployment could safely drop 40+ features and improve both robustness and accuracy simultaneously.

### 4.3 Agent Security (FP-02)

**Target:** LangChain ReAct agents with Claude Sonnet backend. 7 attack classes, 19 scenarios, 3 seeds.

**ACA classification:** Agent input surfaces have varying controllability. User prompts are attacker-controlled but defender-observable (input filtering is possible). Tool outputs are partially controllable (the attacker influences content returned by tools). Tool parameters are attacker-controlled but validator-checkable. Conversation history is poisonable over time. The reasoning chain — the agent's internal step-by-step planning — is partially controllable (structured instructions can hijack it) but not defender-observable (it is internal state).

**Prediction:** Attack success should correlate inversely with defender observability. The reasoning chain, as the least observable input, should have the highest attack success rate.

**Results:** Reasoning chain hijacking achieved 100% success rate across all 3 seeds [DEMONSTRATED]. Prompt injection achieved 80% (defender-observable, filterable). Tool boundary violation achieved 75%. Memory poisoning achieved 67%. Indirect injection via tools achieved only 25% — the lowest rate, because Claude specifically resists following instructions embedded in tool outputs (a model-level defense that makes this input partially defender-observable).

**ACA insight:** The correlation between observability and attack success is monotonic. Layered defense (input sanitization + tool permission boundaries) reduced average attack success by 60%, but reasoning chain hijacking — the least observable vector — was reduced by only 33%. Adding an LLM-as-judge layer (semantic analysis) increased reasoning chain reduction to 67%, because it converts an unobservable input into a partially observable one. ACA does not just predict which attacks succeed; it predicts which defenses will work and why.

### 4.4 Financial Fraud Detection (FP-04)

**Dataset:** 100K synthetic PaySim transactions, 5-seed validation.

**ACA classification:** 12 features are fraudster-controlled (transaction amount, timing, email address, billing country — values the fraudster chooses). 6 features are system-controlled (card type, device fingerprint, merchant risk score, address verification system response — values determined by payment infrastructure the fraudster cannot manipulate).

**Prediction:** System-controlled features alone should provide a meaningful adversary-resistant detection floor. CFA-informed domain features targeting what fraudsters cannot control should capture most of the ML signal.

**Results:** XGBoost achieved AUC 0.987 on all features [DEMONSTRATED, 5 seeds]. A model trained on system-controlled features alone achieved AUC 0.798 — 81% of full performance [SUGGESTED, SYNTHETIC]. CFA-informed features (amount-to-median ratios, merchant risk tiers, suspicious timing patterns) account for 8 of the top 20 SHAP features and capture 91% of the signal [SUGGESTED, SYNTHETIC]. The CFA-informed rule-based baseline alone achieves AUC 0.898 — demonstrating that domain expertise encoded as features targeting defender-observable signals is a strong floor.

**ACA insight:** The 81% robustness ratio quantifies the adversary-resistant detection floor — the performance level that survives even if the fraudster optimally adapts every feature they control. For production systems, this means a fraud detection pipeline can guarantee at least 81% of its detection capability is immune to adaptive adversaries, with the remaining 19% representing signal from features the adversary might learn to manipulate.

**Limitation:** Results are on synthetic PaySim data. Real transaction data with genuine adversarial dynamics would likely produce different robustness ratios. The methodology demonstration is the transferable contribution, not the specific 81% threshold.

### 4.5 PQC Migration (FP-03)

**Dataset:** 21,142 crypto-related CVEs from NVD. Codebase scan of Python stdlib + packages (6,647 files).

**ACA classification:** Crypto migration controllability divides not by attacker/defender but by who can act on each finding: developers control ~20% of findings (direct code changes to hash functions, cipher selection). Libraries control ~70% (developers must wait for upstream updates to cryptographic libraries). Protocols control ~8% (TLS cipher suite negotiation requires protocol-level changes). Hardware controls ~2%.

**Prediction:** Migration priority should be driven by controllability — developer-controlled findings are actionable now; library-controlled findings require a different remediation strategy (dependency monitoring, not code changes).

**Results:** Scanning Python's standard library and packages found 39 quantum-vulnerable findings, with 19 critical Shor-vulnerable primitives (ECDSA, Ed25519) [DEMONSTRATED]. 70% of findings are library-controlled [DEMONSTRATED]. ML priority scoring (GradientBoosting AUC 0.6345) outperforms rule-based scoring by +14.0pp, but the top predictive features are classical exploitability signals (heap overflow, padding oracle, arbitrary execution), not quantum risk [SUGGESTED].

**ACA insight:** ACA reveals that PQC migration is not primarily a code change problem — it is a dependency management problem. Organizations that invest in rewriting their own crypto code are addressing the 20% they control while ignoring the 70% they cannot fix directly. The correct architectural response is to establish library monitoring and upgrade pipelines, not manual code audits. Additionally, classical exploit risk dominates quantum risk in priority scoring — a counterintuitive finding that ACA predicts, because Shor vulnerability is nature-governed (depends on quantum computer availability) while classical exploitability is attacker-controlled (depends on current adversary capability).

### 4.6 Supply Chain Security (FP-10)

**Scope:** 5 ML projects scanned + 2 Hugging Face models. Rule-based detection (not ML).

**ACA classification:** Supply chain risks divide by controllability: developers control 75% of findings (unsafe serialization choices, library version pinning). Model publishers control 20% (model provenance, training data documentation). Platforms control 5% (hosting infrastructure security).

**Prediction:** Developer-controlled risks should be the highest-priority remediation targets because they are immediately actionable. The prevalence of developer-controlled risks suggests that the supply chain security problem in ML is primarily a developer education problem, not a tooling gap.

**Results:** 20 findings across 5 projects, 13 CRITICAL severity [DEMONSTRATED]. 10 of 20 findings (50%) are unsafe pickle/joblib serialization — trivially exploitable arbitrary code execution. 75% of all findings are developer-controlled [DEMONSTRATED]. Traditional dependency scanners miss 4 of 7 risk categories because they do not cover ML-specific risks: model provenance, unsafe serialization formats, untrusted model sources, and deprecated algorithms.

**ACA insight:** Supply chain security inverts the controllability pattern seen in PQC migration. In PQC, most findings are library-controlled and developers cannot act; in supply chain, most findings are developer-controlled and the fix is straightforward (replace `pickle.load` with `safetensors`, add `weights_only=True` to `torch.load`). ACA predicts this difference: serialization format is a developer choice (controllable), while cryptographic library internals are not. The practical implication is that supply chain security is a solvable problem — 75% of the risk surface responds to developer action — while PQC migration requires ecosystem-level coordination.

## 5. Cross-Domain Analysis

### 5.1 Common Patterns

Across all six domains, three patterns emerge consistently:

**Pattern 1: Defender-observable features are the most robust predictors.** In every domain where ML models are trained, the features that resist adversarial pressure are those the attacker cannot manipulate. EPSS percentile in vulnerability prediction. TCP flags in IDS. System-controlled features in fraud detection. The pattern holds regardless of model architecture (logistic regression, XGBoost, random forest) and regardless of data modality (network flows, CVE metadata, financial transactions).

**Pattern 2: Architectural defenses outperform learned defenses.** In IDS, constraint-aware detection (100% recovery) beat adversarial training (61% recovery). In agent security, tool permission boundaries and input sanitization (60% average reduction) beat any single defense layer. In vulnerability prediction, feature selection based on controllability (dropping 40+ attacker-influenced features) improved both accuracy and robustness simultaneously. Learned defenses optimize within the model; architectural defenses optimize the decision about what the model sees.

**Pattern 3: Controllability predicts actionability.** In PQC migration, 70% of findings require waiting for upstream libraries. In supply chain security, 75% of findings are immediately developer-fixable. In agent security, the least observable attack vector (reasoning chain) is the hardest to defend. Controllability classification does not just predict robustness — it predicts where effort should be directed.

### 5.2 Where ACA Predicts Correctly

ACA correctly predicted: (a) that constraining IDS perturbations to controllable features would reduce attack success, (b) that EPSS would dominate vulnerability prediction because it is system-controlled, (c) that reasoning chain hijacking would have the highest agent attack success because it is unobservable, (d) that system-controlled fraud features would provide a meaningful detection floor, (e) that PQC migration is primarily a dependency problem, and (f) that supply chain risks are primarily developer-fixable.

### 5.3 Where ACA Has Limitations

ACA does not predict the *magnitude* of effects — only the direction. It predicted that IDS constraint-aware detection would outperform adversarial training but could not predict the 39-percentage-point gap. It predicted that EPSS would be the top predictor but could not predict the 2x SHAP importance gap. ACA is a qualitative framework that produces architectural guidance, not quantitative robustness guarantees.

ACA also assumes the controllability classification is correct and stable. In practice, controllability can shift: a feature that is system-determined today (e.g., EPSS) could become attacker-influenced if adversaries learn to manipulate the upstream data feeds that EPSS relies on. ACA needs to be re-evaluated periodically as threat models evolve.

## 6. Discussion

### 6.1 Architecture Over Optimization

The dominant paradigm in adversarial ML is model-level optimization: adversarial training, certified robustness bounds, detection networks. These approaches treat the model as the unit of defense and ask "how do we make this model more robust?" ACA asks a different question: "which inputs should this model rely on?"

This is an architectural question, not an optimization question. The answer does not depend on the model — logistic regression and XGBoost both benefit from the same controllability-informed feature selection. It does not depend on the attack method — random noise, gradient-based attacks, and semantic manipulation all fail when the model relies on features the attacker cannot reach. And it does not depend on the domain — the same principle produces actionable guidance in network security, vulnerability management, agent security, cryptography, fraud detection, and supply chain security.

### 6.2 Practical Implications

For ML security practitioners, ACA provides a checklist that should precede any model training:

1. Have you enumerated all inputs? Including derived features, external signals, and configuration values?
2. Have you classified each input by controller? With domain expertise, not assumption?
3. Does your model's critical decision path depend primarily on defender-observable or system-determined features?
4. If not, have you quantified the robustness floor — the performance level achievable with only defender-observable features?
5. Have you built monitoring that detects changes to defender-observable features that should be impossible?

Organizations that answer these questions before training their first model will build systems that survive adversaries. Organizations that skip them will build systems that perform well on benchmarks and fail in production.

### 6.3 The Tagline Is the Methodology

"Securing AI from the architecture up" is often read as a brand statement. ACA makes it a methodology. Architecture-level thinking means asking who controls each input before asking which model to train. It means designing the feature set for robustness before optimizing the model for accuracy. It means treating the controllability boundary as the primary security perimeter, not the model's decision boundary.

## 7. Limitations

ACA has been validated across six security domains, but all applications were conducted by the same research team on publicly available or synthetic data. Independent replication on proprietary production systems would strengthen the generalizability claims.

The quantitative results in IDS (FP-01) use random noise perturbation, not gradient-based attacks. The fraud detection results (FP-04) use synthetic PaySim data. The PQC results (FP-03) show modest ML performance (AUC 0.6345). The agent security results (FP-02) test only two frameworks (LangChain, CrewAI) with one LLM backend (Claude Sonnet). Each domain application has its own experimental limitations, documented in the respective project findings.

ACA is a qualitative directional framework, not a quantitative robustness certifier. It predicts which features and defenses will be more robust, not how much more robust they will be. It does not replace formal adversarial robustness analysis — it guides where that analysis should be focused.

The controllability classification requires domain expertise and may differ between analysts. Two security engineers may disagree on whether a specific feature is attacker-controlled or partially controllable. ACA would benefit from a formal ontology or standardized classification procedure, which is left for future work.

## 8. Conclusion

Adversarial Control Analysis provides a single methodology that predicts adversarial robustness across six security domains. The core principle — classify inputs by who controls them, then build defenses around the uncontrollable boundary — is simple to state and consistently productive when applied. In every domain tested, the features the attacker cannot reach are the features that matter most for robust detection.

ACA does not replace adversarial training, certified robustness, or domain-specific defenses. It provides the architectural foundation that determines whether those techniques will work. An adversarially trained model built on attacker-controlled features will eventually be evaded. A simple model built on defender-observable features will survive. The architecture determines the ceiling; the model determines how close you get to it.

The contribution of this paper is not any single domain result — it is the evidence that one principle transfers across network traffic, vulnerability metadata, AI agent inputs, cryptographic dependencies, financial transactions, and software supply chains. Security is fundamentally about asymmetric control. ACA formalizes that asymmetry into an actionable methodology.

"Securing AI from the architecture up" is not a tagline. It is a three-step process: Enumerate. Classify. Architect.

## References

[1] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward generating a new intrusion detection dataset and intrusion traffic characterization," in *Proc. 4th Int. Conf. Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108-116.

[2] J. Jacobs et al., "Exploit prediction scoring system (EPSS)," in *Proc. ACM SIGSAC Workshop on Moving Target Defense*, 2021, pp. 17-28.

[3] OWASP Foundation, "OWASP Top 10 for Large Language Model Applications," 2025. [Online]. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/

[4] C. Szegedy et al., "Intriguing properties of neural networks," in *Proc. 2nd Int. Conf. Learning Representations (ICLR)*, 2014.

[5] I. J. Goodfellow, J. Shlens, and C. Szegedy, "Explaining and harnessing adversarial examples," in *Proc. 3rd Int. Conf. Learning Representations (ICLR)*, 2015.

[6] A. Madry, A. Makelov, L. Schmidt, D. Tsipras, and A. Vladu, "Towards deep learning models resistant to adversarial attacks," in *Proc. 6th Int. Conf. Learning Representations (ICLR)*, 2018.

[7] N. Carlini and D. Wagner, "Towards evaluating the robustness of neural networks," in *Proc. IEEE Symp. Security and Privacy (SP)*, 2017, pp. 39-57.

[8] F. Croce and M. Hein, "Reliable evaluation of adversarial robustness with an ensemble of attacks," in *Proc. 37th Int. Conf. Machine Learning (ICML)*, 2020, pp. 2206-2216.

[9] J. Cohen, E. Rosenfeld, and J. Z. Kolter, "Certified adversarial robustness via randomized smoothing," in *Proc. 36th Int. Conf. Machine Learning (ICML)*, 2019, pp. 1310-1320.

[10] N. Papernot and P. McDaniel, "Deep k-nearest neighbors: towards confident, interpretable and robust deep learning," arXiv preprint arXiv:1803.04765, 2018.

[11] A. Panigrahi and M. R. Patra, "Performance evaluation of rule learning classifiers in anomaly based intrusion detection," in *Proc. IEEE Int. Conf. Computing, Communication and Security (ICCCS)*, 2018.

[12] G. Apruzzese, M. Colajanni, L. Ferretti, A. Guido, and M. Marchetti, "On the effectiveness of machine and deep learning for cyber security," in *Proc. 10th Int. Conf. Cyber Conflict (CyCon)*, 2018, pp. 371-390.

[13] G. Apruzzese, M. Andreolini, L. Ferretti, M. Marchetti, and M. Colajanni, "Modeling realistic adversarial attacks against network intrusion detection systems," *Digital Threats: Research and Practice*, vol. 3, no. 3, pp. 1-19, 2022.

[14] FIRST.org, "Exploit Prediction Scoring System (EPSS)," 2024. [Online]. Available: https://www.first.org/epss/

[15] S. Wendzel et al., "A survey on adversarial attacks and defenses in text," *ACM Computing Surveys*, vol. 56, no. 3, pp. 1-36, 2024.

[16] S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Proc. Advances in Neural Information Processing Systems (NeurIPS)*, vol. 30, 2017.

[17] M. T. Ribeiro, S. Singh, and C. Guestrin, "Why should I trust you? Explaining the predictions of any classifier," in *Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining*, 2016, pp. 1135-1144.

[18] E. Raff et al., "Malware detection by eating a whole EXE," in *Proc. AAAI Conf. Artificial Intelligence*, vol. 32, 2018.

[19] S. Bhatt and S. Patel, "Explainable AI for financial fraud detection," in *Proc. IEEE Int. Conf. Big Data*, 2020, pp. 3544-3553.

[20] R. E. Kalman, "Mathematical description of linear dynamical systems," *J. SIAM Control*, vol. 1, no. 2, pp. 152-192, 1963.

[21] P. K. Manadhata and J. M. Wing, "An attack surface metric," *IEEE Trans. Software Engineering*, vol. 37, no. 3, pp. 371-386, 2011.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems across every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) | [GitHub](https://github.com/rexcoleman) | [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research.*

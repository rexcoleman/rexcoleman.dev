---
title: "Build Your Own ML Vuln Prioritizer"
date: 2026-03-19
draft: false
tags: ["tutorial", "vulnerability-management", "machine-learning", "epss", "shap", "security"]
format: "tutorial"
audience_side: "from-ai"
image_count: 0
description: "Build a Random Forest model that outperforms CVSS at predicting which vulnerabilities actually get exploited, using only public NVD and EPSS data."
---

## Problem Statement

Your security team triages vulnerabilities by CVSS score. A 9.8 gets patched immediately; a 7.5 waits. But CVSS measures severity, not exploitability. In real-world data, CVSS achieves an AUC of just 0.662 at predicting which CVEs actually get exploited -- barely better than a coin flip. You need a model that predicts exploitation likelihood, not just theoretical severity.

This tutorial walks you through building an ML-based vulnerability prioritizer using public data. By the end, you will have a Random Forest model that beats CVSS by over 20 percentage points on AUC-ROC, and you will understand exactly which features drive those predictions using SHAP.

## Prerequisites

- Python 3.9+ with pip
- Basic familiarity with scikit-learn
- ~2 GB of free disk space for NVD data
- About 30 minutes of compute time on a modern laptop

Install dependencies:

```bash
pip install pandas scikit-learn shap requests tqdm
```

## Step 1: Download NVD and EPSS Data

The National Vulnerability Database (NVD) publishes every CVE with metadata -- CVSS scores, CWE classifications, references, and descriptions. EPSS (Exploit Prediction Scoring System) publishes daily exploit-likelihood scores for every CVE. ExploitDB tells us which CVEs actually have public exploits.

```python
import requests
import pandas as pd
import json
from pathlib import Path

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

# Download EPSS scores (CSV, updated daily)
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
epss_df = pd.read_csv(epss_url, comment="#")
epss_df.to_csv(DATA_DIR / "epss_scores.csv", index=False)
print(f"EPSS scores: {len(epss_df)} CVEs")

# Download NVD data via API (paginated)
# Note: The NVD API has rate limits. Use an API key for faster access.
# Apply at https://nvd.nist.gov/developers/request-an-api-key
def fetch_nvd_page(start_index=0, results_per_page=2000, api_key=None):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(url, params=params, headers=headers)
    resp.raise_for_status()
    return resp.json()

# For the tutorial, start with a smaller slice.
# The full dataset is ~338K CVEs and takes several hours to download.
print("Fetching first page of NVD data...")
page = fetch_nvd_page(results_per_page=2000)
print(f"Total CVEs available: {page['totalResults']}")
```

For ground truth labels, download ExploitDB's `files_exploits.csv` from [https://gitlab.com/exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb). Each row maps to a CVE that has a public exploit.

```python
# After downloading files_exploits.csv from ExploitDB:
exploits_df = pd.read_csv(DATA_DIR / "files_exploits.csv")
exploit_cves = set()
for codes in exploits_df["codes"].dropna():
    for code in str(codes).split(";"):
        code = code.strip()
        if code.startswith("CVE-"):
            exploit_cves.add(code)
print(f"CVEs with public exploits: {len(exploit_cves)}")
```

## Step 2: Engineer Features

The features that predict exploitation are not the ones most people expect. Based on the FP-05 research, the strongest predictors are EPSS percentile (threat intelligence signal), whether the CVE references exploit code, vendor CVE history (deployment ubiquity), and CVSS score. Practitioner keywords like "sql injection" and "remote code execution" help but are not dominant.

```python
import numpy as np
from datetime import datetime

def engineer_features(cve_record):
    """Extract features from a single NVD CVE record."""
    features = {}
    cve_id = cve_record["cve"]["id"]

    # CVSS score (v3 preferred, fall back to v2)
    metrics = cve_record["cve"].get("metrics", {})
    cvss_v3 = None
    cvss_v2 = None
    if "cvssMetricV31" in metrics:
        cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    if "cvssMetricV2" in metrics:
        cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    features["cvss_score"] = cvss_v3 or cvss_v2 or 0.0
    features["cvss_v3"] = cvss_v3 or 0.0
    features["cvss_v2"] = cvss_v2 or 0.0
    features["has_cvss_v3"] = int(cvss_v3 is not None)

    # Description features
    descriptions = cve_record["cve"].get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d["lang"] == "en":
            desc = d["value"]
            break
    features["desc_length"] = len(desc)
    features["desc_word_count"] = len(desc.split())

    # Practitioner keywords
    desc_lower = desc.lower()
    keywords = [
        "sql_injection", "remote_code_execution", "denial_of_service",
        "privilege_escalation", "arbitrary_code", "xss",
        "buffer_overflow", "directory_traversal", "authentication_bypass",
        "information_disclosure", "command_injection"
    ]
    for kw in keywords:
        features[f"kw_{kw}"] = int(kw.replace("_", " ") in desc_lower)

    # Reference features
    refs = cve_record["cve"].get("references", [])
    features["has_exploit_ref"] = int(
        any("exploit" in r.get("url", "").lower() for r in refs)
    )
    features["has_patch_ref"] = int(
        any("patch" in str(r.get("tags", [])).lower() for r in refs)
    )
    features["ref_count"] = len(refs)

    # CWE features
    weaknesses = cve_record["cve"].get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d["value"].startswith("CWE-"):
                cwe_ids.append(d["value"])
    features["has_cwe"] = int(len(cwe_ids) > 0)
    features["cwe_count"] = len(cwe_ids)

    # Temporal features
    pub_date = cve_record["cve"].get("published", "")
    if pub_date:
        pub_dt = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
        features["pub_year"] = pub_dt.year
        features["pub_month"] = pub_dt.month
        features["cve_age_days"] = (datetime.now().astimezone() - pub_dt).days

    # Label
    features["exploited"] = int(cve_id in exploit_cves)
    features["cve_id"] = cve_id

    return features
```

Merge EPSS scores into your feature set:

```python
# After building features_df from NVD records:
epss_df = pd.read_csv(DATA_DIR / "epss_scores.csv")
epss_df = epss_df.rename(columns={"cve": "cve_id", "epss": "epss_score",
                                    "percentile": "epss_percentile"})
features_df = features_df.merge(epss_df[["cve_id", "epss_score", "epss_percentile"]],
                                 on="cve_id", how="left")
features_df["epss_score"] = features_df["epss_score"].fillna(0.0)
features_df["epss_percentile"] = features_df["epss_percentile"].fillna(0.0)
```

## Step 3: Split Temporally and Train a Random Forest

Use a temporal split, not a random split. CVEs published before 2024 go to training; 2024 and later go to test. This prevents future data from leaking into training and simulates how the model would perform on newly published CVEs.

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

# Temporal split
train_df = features_df[features_df["pub_year"] < 2024]
test_df = features_df[features_df["pub_year"] >= 2024]

feature_cols = [c for c in features_df.columns
                if c not in ["cve_id", "exploited", "pub_year"]]
X_train = train_df[feature_cols].fillna(0)
y_train = train_df["exploited"]
X_test = test_df[feature_cols].fillna(0)
y_test = test_df["exploited"]

print(f"Train: {len(X_train)} ({y_train.mean():.1%} exploited)")
print(f"Test:  {len(X_test)} ({y_test.mean():.1%} exploited)")

# Train Random Forest
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

# Evaluate
rf_proba = rf.predict_proba(X_test)[:, 1]
rf_auc = roc_auc_score(y_test, rf_proba)
print(f"Random Forest AUC: {rf_auc:.3f}")
```

## Step 4: Compare Against CVSS Baseline

CVSS scores are the industry standard for vulnerability triage. Use the CVSS score directly as a "prediction" and measure AUC:

```python
# CVSS as a naive predictor
cvss_auc = roc_auc_score(y_test, X_test["cvss_score"])
print(f"CVSS AUC:          {cvss_auc:.3f}")
print(f"Random Forest AUC: {rf_auc:.3f}")
print(f"Improvement:       +{(rf_auc - cvss_auc) * 100:.1f}pp")
```

In the FP-05 research on 338K CVEs, CVSS achieved AUC 0.662 while the ML model achieved 0.864 (Random Forest) to 0.903 (Logistic Regression). That is a +20 to +24 percentage point improvement. CVSS measures how bad a vulnerability could be. ML measures how likely it is to actually be exploited. Those are different questions, and attackers care about the second one.

## Step 5: Explain with SHAP

Numbers alone are not enough for a security team. They need to understand why a particular CVE was ranked high. SHAP (SHapley Additive exPlanations) decomposes each prediction into per-feature contributions.

```python
import shap

# SHAP explainer for Random Forest
explainer = shap.TreeExplainer(rf)
shap_values = explainer.shap_values(X_test.iloc[:500])  # subset for speed

# Global feature importance
shap.summary_plot(shap_values[1], X_test.iloc[:500],
                  feature_names=feature_cols, show=False)
```

In the full FP-05 analysis, the top 5 SHAP features were:

1. **epss_percentile** (mean |SHAP| = 1.096) -- the single strongest predictor, nearly 2x the next feature
2. **has_exploit_ref** (0.573) -- whether the CVE links to proof-of-concept code
3. **cvss_score** (0.430) -- severity helps, but it is not enough alone
4. **vendor_cve_count** (0.429) -- vendors with large CVE histories get targeted because their software is widely deployed
5. **desc_length** (0.367) -- longer descriptions correlate with more complex (and often more exploitable) vulnerabilities

The key insight: EPSS percentile dominates because it encodes real-time threat intelligence. Vendor CVE count captures deployment ubiquity -- attackers invest effort where the payoff is highest. These are signals CVSS was never designed to capture.

## Verification

Check that your model is learning real signal, not memorizing noise:

```python
from sklearn.dummy import DummyClassifier

# Sanity baseline: majority class
dummy = DummyClassifier(strategy="most_frequent")
dummy.fit(X_train, y_train)
dummy_proba = dummy.predict_proba(X_test)[:, 1]
# DummyClassifier with most_frequent will give AUC ~0.500

print(f"Majority class baseline AUC: ~0.500")
print(f"CVSS baseline AUC:           {cvss_auc:.3f}")
print(f"Your model AUC:              {rf_auc:.3f}")
```

If your model AUC is above 0.80, you have a working vulnerability prioritizer that materially outperforms CVSS. If it is below 0.65, check your feature engineering -- the most common mistake is missing the EPSS merge.

## What's Not Solved

**EPSS is hard to beat.** In the full FP-05 experiment, EPSS alone achieved AUC 0.912 -- slightly better than any ML model trained on public data. EPSS is itself an ML model trained on richer data (threat intelligence feeds, social media, exploit activity) that you do not have access to. Your model gets you 99% of EPSS performance using only public data, which matters for organizations that cannot afford commercial threat intel. But if you already have EPSS scores, a simple threshold (EPSS >= 0.01) is a strong baseline.

**Ground truth lags.** ExploitDB labels for recent CVEs are incomplete. Many exploited vulnerabilities from 2024+ have not been added yet. This is a label maturation problem, not a model problem. F1 scores will be low on recent test data regardless of the model.

**Feature controllability matters.** The model is naturally robust to adversarial manipulation because its top features (EPSS, CVSS, vendor history) are defender-observable -- an attacker cannot change them. But if you add features derived from CVE description text, an attacker could submit misleading descriptions to manipulate triage. Build on features you control.

The full methodology, 7-algorithm comparison, ablation study, and adversarial evaluation are in the [vuln-prioritization-ml repo](https://github.com/rexcoleman/vuln-prioritization-ml).

---

*Rex Coleman is securing AI from the architecture up -- building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) | [GitHub](https://github.com/rexcoleman) | [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research -- findings, tools, and curated signal.*

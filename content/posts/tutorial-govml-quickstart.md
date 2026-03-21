---
title: "govML Quickstart: Governed ML in 15 Minutes"
date: 2026-03-19
draft: false
tags: ["tutorial", "govml", "reproducibility", "ml-governance"]
archived: true
hiddenInHomeList: true
categories: ["ML Governance", "Tutorials"]
format: "tutorial"
audience_side: "both"
image_count: 0  # R26: text diagram present (ASCII architecture diagram)
description: "Install govML, scaffold a governed ML project with one command, and learn how contract-driven development prevents the 'I forgot which hyperparameters I used' problem."
cover:
    image: /images/og-tutorial-govml-quickstart.png
    hidden: true
---

> **Note (2026-03-20):** govML is now maintained as internal tooling. This tutorial references a public repository that is no longer available. For the current description of govML's methodology, see [How I Govern AI-Assisted ML Projects](/posts/govml-methodology/).

## Problem Statement

You run an ML experiment. You tweak a hyperparameter. Three weeks later you cannot reproduce the original result because you forgot which config, which seed, which preprocessing step you changed. You have no contracts, no phase gates, no leakage tests. Your experiment notebook is a graveyard of dead cells and commented-out code.

govML solves this by giving every ML project a set of enforceable contracts that lock down your environment, data splits, and experiment parameters before you start training. One command scaffolds the full governance structure. Generators produce executable test suites from your config. This tutorial gets you from zero to a governed project in 15 minutes.

```
init_project.sh
    │
    ├── docs/EXPERIMENT_CONTRACT.md    (what you'll test)
    ├── docs/DATA_CONTRACT.md          (what data you'll use)
    ├── docs/HYPOTHESIS_REGISTRY.md    (what you predict)
    ├── scripts/                       (generated entry points)
    └── tests/                         (generated test stubs)
```

## Prerequisites

- Python 3.9+
- Git
- Bash (Linux/macOS) or WSL (Windows)
- A project idea (even if vague -- you will fill in details later)

## Step 1: Install govML

```bash
# Note: govML is now internal tooling. See /posts/govml-methodology/ for the methodology.
# The clone command below is historical — the public repo is no longer available.
```

govML is a set of templates, profiles, and shell scripts. No pip install, no dependencies to manage, no version conflicts.

Verify it works:

```bash
bash scripts/init_project.sh --help
```

You should see the usage message listing available profiles and flags.

## Step 2: Scaffold a Project with a Profile

Profiles determine which templates get included. Pick the one that matches your project:

| Profile | Templates | When to use |
|---------|:---------:|-------------|
| `minimal` | 3 | Quick prototyping, personal experiments |
| `supervised` | 11 | Standard supervised learning project |
| `security-ml` | 21 | Adversarial evaluation, threat modeling |
| `blog-track` | 14 | Builder-in-public posts with evidence |
| `publication-track` | 28 | Academic-quality research |
| `contract-track` | 42 | Maximum rigor, A+ grade target |

Run the init script:

```bash
bash scripts/init_project.sh ~/my-ml-project --profile supervised --fill
```

The `--fill` flag auto-populates common placeholders (project name from the directory name, current date, Git remote URL). Without `--fill`, you get raw `{{PLACEHOLDER}}` tokens to fill manually.

## Step 3: Walk Through What Gets Generated

Open the project directory:

```bash
ls ~/my-ml-project/docs/
```

With the `supervised` profile, you get:

```
my-ml-project/
├── docs/
│   ├── ENVIRONMENT_CONTRACT.md    # Python version, deps, seeds
│   ├── DATA_CONTRACT.md           # Splits, preprocessing, leakage rules
│   ├── EXPERIMENT_CONTRACT.md     # Hyperparameters, budgets, output schema
│   ├── METRICS_CONTRACT.md        # Metric definitions, thresholds
│   ├── FIGURES_TABLES_CONTRACT.md # Figure specs, captions
│   ├── IMPLEMENTATION_PLAYBOOK.md # Phase plan with done-gates
│   ├── TASK_BOARD.md              # Phase-gated task tracking
│   ├── RISK_REGISTER.md           # Risk table with detection tests
│   ├── DECISION_LOG.md            # Architecture decision records
│   ├── REPORT_ASSEMBLY_PLAN.md    # Report outline + page budget
│   └── REPRODUCIBILITY_SPEC.md    # Single-doc reproduction guide
├── project.yaml                   # Config for code generators
└── tests/
    └── test_leakage_tripwires.py  # Auto-generated leakage tests
```

Each contract is a markdown file with sections you fill in. Here is what the most important ones do:

**ENVIRONMENT_CONTRACT.md** locks your Python version, package versions, and random seeds. When someone asks "can I reproduce this?" the answer is "follow the environment contract."

```markdown
## Seeds
- Primary seed: 42
- Multi-seed validation: [42, 123, 456, 789, 1024]
- All random state set via: `np.random.seed()`, `torch.manual_seed()`
```

**DATA_CONTRACT.md** defines your data source, split strategy, and leakage prevention rules. The most common ML failure is train/test contamination, and the data contract makes it explicit.

```markdown
## Split Strategy
- Method: temporal (pre-2024 train / 2024+ test)
- Rationale: prevents future data leaking into training
- Train size: ~234K
- Test size: ~103K
- Class balance: train 10.5% positive, test 0.3% positive
```

**EXPERIMENT_CONTRACT.md** defines every hyperparameter, training budget, and stopping criterion before you start running experiments. This prevents p-hacking and post-hoc rationalization.

## Step 4: Use the Generators

govML includes 20+ code generators that produce executable artifacts from your `project.yaml` config.

First, edit `project.yaml` to match your project:

```yaml
project_name: my-ml-project
seed: 42
seeds: [42, 123, 456, 789, 1024]
algorithms:
  - name: LogisticRegression
    library: sklearn
  - name: RandomForest
    library: sklearn
  - name: XGBoost
    library: xgboost
data:
  source: "NVD API"
  split: temporal
  train_cutoff: "2024-01-01"
phases:
  - name: data_acquisition
    checks:
      - "data/raw/ directory exists"
      - "data/splits/split_info.json exists"
  - name: baseline
    checks:
      - "outputs/baselines/ directory exists"
  - name: experiments
    checks:
      - "outputs/models/ directory exists"
  - name: analysis
    checks:
      - "outputs/explainability/ directory exists"
```

Then run generators:

```bash
# Generate leakage prevention tests
python scripts/generators/gen_leakage_tests.py \
    --config ~/my-ml-project/project.yaml \
    --output ~/my-ml-project/tests/test_leakage_tripwires.py

# Generate phase gate checker
python scripts/generators/gen_phase_gates.py \
    --config ~/my-ml-project/project.yaml \
    --output ~/my-ml-project/scripts/check_gates.sh

# Generate learning curve runner
python scripts/generators/gen_learning_curves.py \
    --config ~/my-ml-project/project.yaml \
    --output ~/my-ml-project/scripts/run_learning_curves.py
```

The leakage test generator produces a pytest file that checks for common contamination patterns:

```python
# Auto-generated by govML gen_leakage_tests.py
def test_no_train_test_overlap():
    """Ensure no sample appears in both train and test sets."""
    train_ids = load_split_ids("train")
    test_ids = load_split_ids("test")
    overlap = set(train_ids) & set(test_ids)
    assert len(overlap) == 0, f"Found {len(overlap)} overlapping samples"

def test_temporal_split_integrity():
    """Ensure all train samples are before the cutoff date."""
    train_dates = load_split_dates("train")
    assert all(d < "2024-01-01" for d in train_dates), \
        "Found training samples after temporal cutoff"
```

## Step 5: Use the Contract Change Protocol

When you need to change a hyperparameter, a split ratio, or a feature set, do not just change the code. Follow the contract change protocol:

1. **Record the decision** in `DECISION_LOG.md` with an ADR (Architecture Decision Record)
2. **Update the contract** (experiment contract, data contract, etc.)
3. **Regenerate downstream artifacts** (re-run generators if the change affects generated code)
4. **Commit the contract change and code change together**

```markdown
## ADR-0003: Switch from random split to temporal split

**Status:** Accepted
**Date:** 2026-03-19
**Context:** Random split allows future CVEs to leak into training.
**Decision:** Temporal split at 2024-01-01 boundary.
**Consequences:** Test set has extreme class imbalance (0.3% positive).
  F1 will be depressed. Use AUC for model selection.
```

This protocol eliminates "I changed something but I don't remember what." Every change is recorded, every contract is updated, every downstream artifact is regenerated.

## Verification

Your govML setup is working if:

1. `~/my-ml-project/docs/` contains all the contracts for your chosen profile.
2. `project.yaml` reflects your actual project configuration.
3. `tests/test_leakage_tripwires.py` runs and passes (even before you have data -- the tests should handle missing data gracefully or skip).
4. You can explain the split strategy, seed policy, and phase gates by reading the contracts alone, without looking at any code.

Run the tests:

```bash
cd ~/my-ml-project
python -m pytest tests/ -v
```

## What's Not Solved

**govML enforces structure, not quality.** The contracts ensure you document your split strategy, but they do not tell you whether your split strategy is correct. A temporal split is not always better than a random split -- it depends on your problem. govML prevents you from forgetting to document the decision; it does not make the decision for you.

**Phase gates check file existence, not file content.** The automated gate check verifies that `outputs/baselines/` exists, but it cannot verify that the baselines are correct. Content quality still requires human judgment. The govML-as-MCP research identified this as the explicit boundary: 6 agent-safe tasks (template filling, gate checking, hygiene scanning) and 5 human-required tasks (thesis formulation, research question design, finding interpretation, tradeoff judgment, narrative voice).

**50+ templates is a lot.** The contract-track profile gives you maximum rigor, but for a weekend project it is overkill. Start with `minimal` (3 templates) or `supervised` (11 templates) and graduate to higher profiles as your project matures.

govML is used across 9 research projects with 469+ tests.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research -- findings, tools, and curated signal.*

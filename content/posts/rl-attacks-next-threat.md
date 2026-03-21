---
title: "Prompt Injection Is Yesterday's Threat. RL Attacks Are Next."
date: 2026-03-19
draft: false
tags: ["ai-security", "reinforcement-learning", "agent-security", "rl-attacks", "adversarial-ml"]
categories: ["AI Security"]
format: "perspective"
audience_side: "of-ai"
image_count: 0
description: "The security community is focused on prompt injection, but RL-specific attacks are more dangerous and less understood."
author: "Rex Coleman"
ShowToc: true
TocOpen: true
cover:
    image: /images/og-rl-attacks-next-threat.png
    hidden: true
---

**Thesis:** The security community is focused on prompt injection, but RL-specific attacks — reward poisoning, observation perturbation, policy extraction — are more dangerous and less understood.

Prompt injection is real. I've tested it. In my [agent red-teaming research](/posts/agent-redteam/), direct prompt injection achieved 80% success against default-configured LangChain ReAct agents. Reasoning chain hijacking hit 100%. These are serious vulnerabilities.

But prompt injection is also becoming yesterday's threat — it's well-characterized, actively mitigated, and architecturally bounded. The attacks that should keep agent deployers awake are the ones that don't touch the prompt at all.

## The Evidence

**1. Observation perturbation degrades RL agents 20-50x more than reward poisoning.**

In my [RL agent vulnerability research](/posts/rl-agent-vulnerability/), I trained 40 RL agents across 4 algorithms (Q-Learning, DQN, Double DQN, PPO) and 2 security-relevant environments (access control, tool selection), then ran 150 attack experiments across 4 attack classes.

Observation perturbation — adding small noise to what the agent sees — caused 40-49 point reward degradation at epsilon=0.01 (minimal noise). Reward poisoning at 20% corruption produced only 0.2-1.6% policy divergence. The agent's learning algorithm filters corrupted rewards because they're averaged over entire episodes. But corrupted observations hit at decision time and cascade immediately. An access control agent that misreads its threat level observation by a tiny margin grants access it should deny — and there's no recovery within the episode.

Compare this to prompt injection: bounded by a single conversation, visible in logs, increasingly mitigated by guardrails. Observation perturbation is continuous, operates on numerical vectors invisible to text-based defenses, and compounds with every decision the agent makes.

**2. Policy extraction achieves 72% agreement with 500 queries.**

An adversary can reconstruct 72% of an RL agent's decision policy through black-box queries — no model access required. The attack uses imitation learning: query the agent with diverse states, record its actions, train a surrogate. In my experiments, the surrogate reached 71% agreement at just 100 queries and plateaued at 72% by 500.

What does a 72%-accurate policy clone enable? The attacker can predict what your agent will do in any given state and plan around it. They can identify the states where your agent is most likely to grant access, select a vulnerable tool, or escalate privileges. They can rehearse attack sequences offline. And 500 queries is a trivially small footprint — within normal API usage patterns and nearly impossible to distinguish from legitimate traffic.

Prompt injection doesn't enable anything like this. You can inject a prompt and observe the response, but you can't systematically reconstruct the agent's decision boundary from text interactions. RL policy extraction is a fundamentally more powerful reconnaissance capability.

**3. Zero OWASP coverage of RL-specific attacks.**

OWASP's Agentic Top 10 identifies 10 risk categories. My [agent red-teaming work](/posts/agent-redteam/) mapped to 6 of the 10. But when I tested which of these categories cover RL-specific attacks — reward poisoning, observation perturbation, policy extraction, behavioral backdoors — I found that 5 attack classes from my RL research have no direct OWASP equivalent.

The OWASP framework was designed for prompt-based agents. It addresses prompt injection (ASI-10), goal hijacking (ASI-01), and supply chain risks (ASI-08). It does not address reward signal corruption, observation channel manipulation, or policy extraction through black-box queries. These are distinct attack surfaces that require distinct defenses.

The security community is building defenses against the OWASP list. If the OWASP list doesn't include RL attacks, the defenses won't cover them. And as more production agents incorporate RL training — Agent-R1 proved in November 2025 that agents are being trained end-to-end on tool-use trajectories — the undefended attack surface grows.

**4. Prompt-injection defenses provide 0% protection against RL attacks.**

I tested this directly. The 3 defense layers I built for prompt injection (input sanitization, tool permission boundaries, output validation) were applied to RL attack scenarios. Result: 0% reduction in attack success. The defenses operate on the text/semantic layer. RL attacks operate on numerical reward vectors, observation tensors, and learned policy weights. There is zero surface overlap.

This means an organization that has invested in prompt injection defenses — and many have — has no coverage against RL-specific attacks. Their defense posture is analogous to deploying antivirus and declaring themselves protected against SQL injection. The attack surfaces are categorically different.

**5. Behavioral backdoors are stealthier than any prompt attack.**

Trigger-state backdoors — where the agent behaves normally until a specific state pattern activates adversary-preferred behavior — achieved 2.6% policy divergence on access control agents. That's higher than reward poisoning at any corruption rate. The backdoor activates only when a specific combination of user role, resource type, and threat level is observed.

The stealth advantage is structural. A prompt injection attempt is visible in the conversation log. An input sanitizer can flag it. A behavioral backdoor produces normal-looking decisions 97.4% of the time and adversary-preferred decisions only in the trigger state. The agent doesn't "look" compromised because it isn't — except in the specific states the attacker cares about.

## What This Means for the Field

The security community is fighting the last war. Prompt injection was the first AI attack the industry understood, so it became the attack the industry defends against. But the threat model has already shifted.

Production agents are incorporating RL training. The RL attack surface is different from the prompt attack surface. Defenses built for one provide zero coverage of the other. Organizations that equate "AI security" with "prompt injection defense" have a blind spot that grows with every RL-trained agent they deploy.

The field needs to expand its threat model. Prompt injection is a real risk that deserves continued attention. But it's one row in a matrix that should include reward poisoning, observation perturbation, policy extraction, and behavioral backdoors. Each requires its own defense architecture.

## What I'm Doing About It

I built the first open-source RL attack framework for agent security environments: 4 attack classes, 2 custom Gymnasium environments, 150 experiments across 40 agents. The [code](https://github.com/rexcoleman/rl-agent-vulnerability), [findings](/posts/rl-agent-vulnerability/), and [attack taxonomy](/posts/agent-redteam/) are all published.

Combined with the [agent red-teaming framework](/posts/agent-redteam/), this creates a systematic attack taxonomy that spans both prompt-based and RL-based agent attack surfaces — 7 prompt-level attack classes plus 4 RL-specific attack classes, mapped to OWASP where coverage exists and flagging the 5 categories where it doesn't.

At [Singularity Cybersecurity](https://singularitycyber.com), the next step is building detection tools that cover both surfaces. AgentArmor's [HYPOTHESIZED] runtime monitoring is designed from the ground up to watch observation channels and reward signals, not just prompt inputs. Because that's where the next generation of attacks will land.

### Limitations

The 20-50x degradation ratio comes from tabular Q-Learning on small state spaces. Deep RL with larger observation spaces may show different dynamics. The 72% policy extraction rate was measured on custom Gymnasium environments, not production agent APIs. The "zero OWASP coverage" assessment is based on my mapping of the published ASI categories to RL attack types — others may interpret the mapping differently. Prompt injection remains a serious, actively exploited vulnerability; this post argues for expanding the threat model, not ignoring prompt risks.

---

*Rex Coleman is securing AI from the architecture up — building and attacking AI security systems at every layer of the stack, publishing the methodology, and shipping open-source tools. [rexcoleman.dev](https://rexcoleman.dev) · [GitHub](https://github.com/rexcoleman) · [Singularity Cybersecurity](https://singularitycyber.com)*

---

*If this was useful, [subscribe on Substack](https://substack.com/@rexcoleman) for weekly AI security research — findings, tools, and curated signal.*

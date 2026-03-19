# I Red-Teamed AI Agents: Here's How They Break (and How to Fix Them)

I sent 19 attack scenarios at a default-configured LangChain ReAct agent powered by Claude Sonnet. 13 succeeded. Validated prompt injection on CrewAI — same 80% rate. Built an open-source framework that systematizes 7 attack classes, 5 of which aren't in OWASP LLM Top 10 or MITRE ATLAS.

**The standout finding: reasoning chain hijacking achieved 100% success rate.** The attack exploits the agent's core capability — following structured plans — as the attack vector. Example payload: a step-by-step plan that looks like a legitimate task but instructs the agent to find API keys, compute on them, and write them to a file. No injection patterns, no special characters. Pattern-based defenses can't detect it because there's nothing anomalous.

Attack success rates by class: Direct Prompt Injection 80%, Tool Permission Boundary Violation 75%, Memory/Context Poisoning 67%, Indirect Injection via Tools 25%, Reasoning Chain Hijacking 100%.

I built three defense layers. The layered defense reduces average attack success by 60%. But reasoning chain hijacking only drops from 100% to 67%. The only layer that catches it is an LLM-as-Judge (semantic defense) — a separate LLM call evaluating whether a request contains hidden exfiltration intent. Cost: ~$0.002 per request.

The deeper architectural finding: attack success correlates inversely with defender observability. User prompts (visible, filterable) = 80% success. Tool outputs (partially observable) = 25%. Reasoning chain (internal, invisible to defenders) = 100%. The less you can observe, the more vulnerable you are.

Every agent framework implementing ReAct, chain-of-thought, or plan-and-execute patterns shares this vulnerability. The reasoning loop is the feature AND the attack surface.

Caveat: tested on default-configured agents with Claude backend. Production-hardened deployments would likely show different rates. Total API cost: ~$2 in Claude Sonnet tokens.

Full write-up with code: https://rexcoleman.dev/posts/agent-redteam/

Repo: https://github.com/rexcoleman/agent-redteam-framework

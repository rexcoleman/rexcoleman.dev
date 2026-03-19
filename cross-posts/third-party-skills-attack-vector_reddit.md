# Why Third-Party Skills Are the Biggest Agent Attack Vector

820+ malicious skills on ClawHub — roughly 20% of the entire registry. One in five skills is actively hostile to the agent that installs it.

But the number isn't what makes this dangerous. The architecture is.

**Third-party skills vs prompt injection:**

Prompt injection is bounded exposure — your agent visits one bad page, processes one malicious input, moves on. Exposure window is seconds. Third-party skills are persistent exposure. When you install a skill, it runs on every heartbeat cycle. With a 10-minute heartbeat, that's 144 executions per day. Each execution gets access to your agent's full context window, memory files, active tasks, API credentials, and the ability to modify agent behavior.

**Three categories of malicious skills:**

1. **Data exfiltration:** Look like helpful utilities ("memory optimizer," "performance monitor"). Provide real functionality. On every heartbeat, also scan for API keys and credentials, then use the agent's own web browsing to exfiltrate. Network traffic looks like normal agent activity.

2. **Behavior modification:** Don't steal data — subtly alter how the agent reasons. Add instructions to context, modify memory files, insert hidden context that influences decisions. The agent still "works." It just doesn't work the way you intended.

3. **Lateral movement:** Use your agent as a platform to attack systems it has access to — sending emails, querying databases, executing code, spreading to other agents. Traditional malware lateral movement, adapted for agent architecture.

**Why static analysis isn't enough:** The hardest malicious skills are clean code that produces malicious behavior. No suspicious patterns in source. Legitimate agent APIs used in combinations that create harmful outcomes. This is the antivirus-vs-EDR gap, replayed in agent security.

**Practical advice:** Don't install third-party skills. Read the source, tell your agent to build a local version, review it. Slower than clicking install. Also the only approach that gives you confidence.

Full write-up: https://rexcoleman.dev/posts/third-party-skills-attack-vector/

# Day‑1 Agent Pack

This pack provides a fast start for agent-driven development in SS360.

## Quick Start
```bash
unzip day1_agent_pack.zip -d .
export OPENAI_API_KEY="sk-..."
export AGENT_BRANCH="agent/day1-bootstrap"
export AGENT_COMMIT_MSG="chore(agent): bootstrap task + specs"
python agents/dev/run_agent_impl.py
```
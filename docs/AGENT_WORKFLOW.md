# SS360 Agent-Driven Development Workflow

This document describes how SS360 uses AI agents to automate and coordinate development tasks.

## Overview

SS360 uses three main agents coordinated by the PM Agent:

1. **Product Manager (PM) Agent**
   - Primary coordinator for development workflow
   - Triages issues and creates tasks
   - Coordinates with dev agent for implementation
   - Manages task priorities and dependencies

2. **Development Agent**
   - Triggered by PM agent (not directly)
   - Implements features and fixes
   - Creates PRs for review
   - Updates task status through PM agent

3. **Test Agent**
   - Runs daily comprehensive tests
   - Validates PRs through PM agent coordination
   - Reports results back to PM agent

## Workflow

1. **Issue Creation & PM Agent**
   - New issue created in SS360 repository
   - PM Agent automatically:
     * Analyzes issue content
     * Sets priority and labels
     * Creates development tasks
     * Coordinates with dev agent when ready

2. **Development (via PM Agent)**
   - PM Agent triggers dev agent for ready tasks
   - Dev Agent:
     * Creates implementation PRs
     * Updates PM agent on progress
     * Handles review feedback

3. **Testing**
   - Daily comprehensive test runs at 00:00 UTC
   - PM Agent can trigger additional test runs
   - Test results feed back to PM agent for coordination

## Environment Setup

Required secrets in GitHub:
- `GH_TOKEN` - GitHub access token
- `DATABASE_URL` - PostgreSQL connection string
- `OPENAI_API_KEY` - OpenAI API key
- `HOST_IP` - Agent service host IP (178.156.204.70)

Agent services configuration:
```bash
# Docker deployment
docker compose -f docker-compose.yml up -d
```

## Monitoring

1. **GitHub Issues**
   - PM Agent updates issue with status and next steps
   - Links to related PRs and test results
   - Priority and label updates

2. **Agent Logs**
   ```bash
   # View PM agent logs
   docker compose logs -f agent-hub-pm
   
   # View all agent logs
   docker compose logs -f
   ```

3. **Workflow Runs**
   - Check GitHub Actions for workflow status
   - Daily test run results
   - PM agent activity logs

## Best Practices

1. **Creating Issues**
   - Use clear, descriptive titles
   - Include acceptance criteria
   - Add relevant context for PM agent
   - Follow template if provided

2. **Working with PM Agent**
   - Let PM agent manage task coordination
   - Monitor issue comments for updates
   - Update issue with additional context if needed

3. **Emergency Procedures**
   - For urgent issues, add `priority:high` label
   - PM agent will expedite high-priority tasks
   - Manual override available through admin commands
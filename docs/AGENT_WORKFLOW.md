# SS360 Agent-Driven Development Workflow

This document describes how SS360 uses AI agents to automate and coordinate development tasks.

## Overview

SS360 uses three main agents:
1. Product Manager (PM) Agent - Triages issues and coordinates development
2. Development Agent - Implements features and fixes
3. Test Agent - Validates changes and ensures quality

## Workflow

1. **Issue Creation**
   - Create a new issue in the SS360 repository
   - PM Agent automatically analyzes the issue
   - PM Agent creates development tasks and assigns priorities

2. **Development**
   - Dev Agent picks up tasks marked as 'dev-ready'
   - Creates PRs with implementations
   - Updates issue status

3. **Testing**
   - Test Agent automatically runs on new PRs
   - Validates changes against requirements
   - Reports results as PR comments

## Environment Setup

1. Ensure required secrets are set in GitHub:
   - `GH_TOKEN` - GitHub access token
   - `DATABASE_URL` - PostgreSQL connection string
   - `OPENAI_API_KEY` - OpenAI API key
   - `HOST_IP` - Agent service host IP

2. Agent services should be running on the host (178.156.204.70):
   ```bash
   docker compose up -d
   ```

## Creating Issues

When creating issues:
1. Use clear, descriptive titles
2. Include acceptance criteria
3. Add relevant labels
4. PM Agent will automatically process new issues

## Monitoring Progress

1. Check issue comments for agent updates
2. View workflow runs in GitHub Actions
3. Monitor agent logs in Docker:
   ```bash
   docker compose logs -f agent-hub
   ```
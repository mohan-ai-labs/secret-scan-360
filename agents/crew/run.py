import os, json
from crewai import Agent, Task, Crew, Process
from tools import ensure_branch, commit_push_as_user, call_api_scan, write_report

REPO_DIR        = os.getenv("GITHUB_WORKSPACE", ".")
REPO_FULL_NAME  = os.getenv("GITHUB_REPOSITORY", "mohan-ai-labs/secret-scan-360")
BRANCH          = os.getenv("AGENT_BRANCH", "agent/scan-and-report")
API_BASE        = os.getenv("SS360_API_BASE", "http://localhost:8000")
API_TOKEN       = os.getenv("SS360_API_TOKEN")  # optional
# Public repo example:
DEFAULT_REPO_URL = os.getenv("SCAN_REPO_URL", f"https://github.com/{REPO_FULL_NAME}.git")

# For private repos, set SCAN_REPO_URL to:
#  https://x-access-token:${GITHUB_TOKEN}@github.com/<owner>/<repo>.git

dev = Agent(
    role="Full-stack Developer Agent",
    goal="Run SS360 scan and publish a report as a small PR.",
    backstory="Senior engineer focused on safe, auditable automation.",
    llm="gpt-4o-mini",
    allow_code_execution=True,
    max_iter=3
)

def implement():
    ensure_branch(REPO_DIR, BRANCH)
    # 1) Call the scan API
    result = call_api_scan(API_BASE, DEFAULT_REPO_URL, token=API_TOKEN)
    # 2) Write report files
    json_path, md_path = write_report(REPO_DIR, result)
    # 3) Commit as the human owner, not the bot
    commit_push_as_user(REPO_DIR, BRANCH, "chore(report): add SS360 scan report")
    # 4) Print a short summary for workflow logs
    return {"scan_id": result.get("scan_id"), "true_hits": result.get("true_hits"), "report_json": json_path, "report_md": md_path}

t1 = Task(description="Run SS360 scan and write report", agent=dev, expected_output="Report files created and pushed", func=implement, output_json=True)
crew = Crew(agents=[dev], tasks=[t1], process=Process.sequential)
print(json.dumps(crew.kickoff(), indent=2))

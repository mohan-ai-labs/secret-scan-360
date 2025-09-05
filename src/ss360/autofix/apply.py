# SPDX-License-Identifier: MIT
"""
Autofix plan execution - applies remediation plans.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Dict, Any, List
from pathlib import Path

from .planner import PlanItem, ActionType


class AutofixApplier:
    """Applies autofix plans to remediate security findings."""
    
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.applied_actions = []
    
    def apply_plan(
        self,
        plan_items: List[PlanItem],
        confirmation_required: bool = True
    ) -> Dict[str, Any]:
        """
        Apply the autofix plan.
        
        Args:
            plan_items: List of planned actions
            confirmation_required: If True, require explicit confirmation
            
        Returns:
            Dictionary with execution results
        """
        if confirmation_required and not self.dry_run:
            if not self._confirm_dangerous_actions(plan_items):
                return {"status": "cancelled", "reason": "User cancelled operation"}
        
        results = {
            "status": "success",
            "applied": [],
            "failed": [],
            "skipped": []
        }
        
        for item in plan_items:
            try:
                if item.action == ActionType.REMOVE_LITERAL:
                    self._apply_remove_literal(item, results)
                elif item.action == ActionType.REPLACE_WITH_SECRET_REF:
                    self._apply_replace_with_secret_ref(item, results)
                elif item.action == ActionType.REVOKE_TOKEN:
                    self._apply_revoke_token(item, results)
                elif item.action == ActionType.DEACTIVATE_KEY:
                    self._apply_deactivate_key(item, results)
                else:
                    results["skipped"].append({
                        "item": item.description,
                        "reason": f"Unknown action type: {item.action}"
                    })
            except Exception as e:
                results["failed"].append({
                    "item": item.description,
                    "error": str(e)
                })
        
        # Open PR if any file changes were made
        if results["applied"] and not self.dry_run:
            pr_result = self._create_pull_request(results["applied"])
            results["pull_request"] = pr_result
        
        return results
    
    def _apply_remove_literal(self, item: PlanItem, results: Dict[str, Any]):
        """Remove literal secret from file."""
        if self.dry_run:
            results["applied"].append({
                "action": "remove_literal",
                "file": item.path,
                "line": item.line,
                "dry_run": True
            })
            return
        
        # Read file
        file_path = Path(item.path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {item.path}")
        
        lines = file_path.read_text().splitlines()
        
        # Replace the line
        if 0 <= item.line - 1 < len(lines):
            original_line = lines[item.line - 1]
            lines[item.line - 1] = original_line.replace(item.original_value, item.replacement)
            
            # Write back
            file_path.write_text("\n".join(lines) + "\n")
            
            results["applied"].append({
                "action": "remove_literal",
                "file": item.path,
                "line": item.line,
                "replacement": item.replacement
            })
    
    def _apply_replace_with_secret_ref(self, item: PlanItem, results: Dict[str, Any]):
        """Replace literal with secret manager reference."""
        # Same as remove_literal for now
        self._apply_remove_literal(item, results)
    
    def _apply_revoke_token(self, item: PlanItem, results: Dict[str, Any]):
        """Revoke GitHub token via API."""
        if self.dry_run:
            results["applied"].append({
                "action": "revoke_token",
                "provider": item.provider,
                "token_hint": f"****{item.original_value[-4:]}",
                "dry_run": True
            })
            return
        
        # Import provider and revoke
        if item.provider == "github":
            from .providers.github import revoke_pat
            success = revoke_pat(item.original_value)
            if success:
                results["applied"].append({
                    "action": "revoke_token",
                    "provider": "github",
                    "token_hint": f"****{item.original_value[-4:]}"
                })
            else:
                raise Exception("Failed to revoke GitHub PAT")
    
    def _apply_deactivate_key(self, item: PlanItem, results: Dict[str, Any]):
        """Deactivate AWS access key."""
        if self.dry_run:
            results["applied"].append({
                "action": "deactivate_key",
                "provider": item.provider,
                "key_hint": f"****{item.original_value[-4:]}",
                "dry_run": True
            })
            return
        
        # Import provider and deactivate
        if item.provider == "aws":
            from .providers.aws import deactivate_access_key
            success = deactivate_access_key(item.original_value)
            if success:
                results["applied"].append({
                    "action": "deactivate_key",
                    "provider": "aws",
                    "key_hint": f"****{item.original_value[-4:]}"
                })
            else:
                raise Exception("Failed to deactivate AWS Access Key")
    
    def _confirm_dangerous_actions(self, plan_items: List[PlanItem]) -> bool:
        """Confirm dangerous actions with user."""
        dangerous_actions = [
            item for item in plan_items 
            if not item.reversible
        ]
        
        if not dangerous_actions:
            return True
        
        print("WARNING: The following actions cannot be reversed:")
        for item in dangerous_actions:
            print(f"  - {item.description}")
        
        response = input("\nContinue? (yes/no): ").lower().strip()
        return response in ("yes", "y")
    
    def _create_pull_request(self, applied_actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a pull request with the autofix changes."""
        try:
            # Create branch
            branch_name = "autofix/secret-remediation"
            subprocess.run(["git", "checkout", "-b", branch_name], check=True)
            
            # Commit changes
            subprocess.run(["git", "add", "."], check=True)
            
            commit_msg = "🔒 Autofix: Remove exposed secrets\n\nActions taken:\n"
            for action in applied_actions:
                if action.get("action") == "remove_literal":
                    commit_msg += f"- Replaced secret in {action['file']}:{action['line']}\n"
                elif action.get("action") == "revoke_token":
                    commit_msg += f"- Revoked {action['provider']} token {action['token_hint']}\n"
            
            subprocess.run(["git", "commit", "-m", commit_msg], check=True)
            
            # Create PR body
            pr_body = self._generate_pr_body(applied_actions)
            
            # Push and create PR
            subprocess.run(["git", "push", "-u", "origin", branch_name], check=True)
            
            # Use gh CLI if available
            try:
                result = subprocess.run([
                    "gh", "pr", "create",
                    "--title", "🔒 Autofix: Remove exposed secrets",
                    "--body", pr_body
                ], capture_output=True, text=True, check=True)
                
                return {
                    "status": "success",
                    "branch": branch_name,
                    "pr_url": result.stdout.strip()
                }
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    "status": "branch_created",
                    "branch": branch_name,
                    "message": "Branch created, but PR creation failed. Create manually."
                }
                
        except subprocess.CalledProcessError as e:
            return {
                "status": "failed",
                "error": str(e)
            }
    
    def _generate_pr_body(self, applied_actions: List[Dict[str, Any]]) -> str:
        """Generate PR body with remediation checklist."""
        body = """## Secret Remediation Checklist

This PR automatically removes exposed secrets found by SS360.

### Actions Taken
"""
        
        for action in applied_actions:
            if action.get("action") == "remove_literal":
                body += f"- [x] Replaced secret in `{action['file']}:{action['line']}`\n"
            elif action.get("action") == "revoke_token":
                body += f"- [x] Revoked {action['provider']} token `{action['token_hint']}`\n"
        
        body += """
### Manual Steps Required
- [ ] Verify that the application still works with the secret references
- [ ] Update CI/CD pipelines if needed
- [ ] Notify team members about the secret rotation
- [ ] Review and approve this PR

### Security Notes
- All exposed secrets have been replaced with secure references
- Tokens have been revoked to prevent unauthorized access
- This change was automatically generated by SS360

**⚠️ Important**: Do not merge this PR until you've verified that all secret references are correctly configured.
"""
        return body
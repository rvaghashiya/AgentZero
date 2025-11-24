"""
Simulated GitHub MCP Server
Implements operation-level access control with OBO token validation
"""
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class GitHubOperation:
    """Represents a GitHub API operation"""
    name: str
    required_scope: str
    description: str
    is_write_operation: bool

class MockGitHubData:
    """Simulated GitHub data for demonstration"""
    
    REPOS = {
        "public/website": {
            "visibility": "public",
            "files": ["index.html", "style.css", "README.md", "app.js"],
            "readme": "# Company Website\nPublic facing marketing site\nContact: marketing@company.com",
            "description": "Public company website repository"
        },
        "private/api-service": {
            "visibility": "private",
            "files": ["server.py", "config.yaml", "database.py", "auth.py", "secrets.env"],
            "readme": "# API Service\nInternal microservice\nContains authentication logic and database connections",
            "description": "Internal API service with sensitive credentials"
        },
        "private/financial-data": {
            "visibility": "private",
            "files": ["quarterly_report.xlsx", "sensitive_data.csv", "audit_log.txt", "payroll.db"],
            "readme": "# Financial Data\n CONFIDENTIAL - Financial records\nAccess restricted to Finance team only",
            "description": "Confidential financial records and reports"
        }
    }
    
    ISSUES = {
        "public/website": [
            {"id": 1, "title": "Update homepage banner", "labels": ["enhancement"], "author": "marketing@company.com"},
            {"id": 2, "title": "Fix mobile responsive design", "labels": ["bug"], "author": "dev@company.com"},
            {"id": 3, "title": "Add contact form", "labels": ["feature"], "author": "marketing@company.com"}
        ],
        "private/api-service": [
            {"id": 10, "title": "Database performance issue", "labels": ["critical"], "author": "dev@company.com"},
            {"id": 11, "title": "Add rate limiting", "labels": ["security"], "author": "dev@company.com"},
            {"id": 12, "title": "Implement OAuth2", "labels": ["enhancement"], "author": "dev@company.com"}
        ],
        "private/financial-data": [
            {"id": 20, "title": "Q4 audit preparation", "labels": ["audit"], "author": "finance@company.com"},
            {"id": 21, "title": "Update expense reports", "labels": ["admin"], "author": "finance@company.com"}
        ]
    }

class GitHubMCPServer:
    """
    Simulated MCP Server for GitHub operations
    Implements identity validation and least privilege access control
    
    Security Features:
    - OBO token validation before every operation
    - Scope-based permission checking
    - Private/public repository filtering
    - Operation-level access control
    - Complete audit logging with identity chains
    """
    
    def __init__(self, token_service):
        self.token_service = token_service
        self.audit_log: List[Dict] = []
        
        # Define available operations and their required permissions
        self.operations = {
            "list_repositories": GitHubOperation(
                "list_repositories",
                "github:read_public_repos",
                "List accessible repositories",
                False
            ),
            "read_file": GitHubOperation(
                "read_file",
                "github:read_code",
                "Read file contents from repository",
                False
            ),
            "list_issues": GitHubOperation(
                "list_issues",
                "github:read_issues",
                "List issues in repository",
                False
            ),
            "create_issue": GitHubOperation(
                "create_issue",
                "github:write_issues",
                "Create new issue",
                True
            ),
            "create_branch": GitHubOperation(
                "create_branch",
                "github:create_branch",
                "Create new branch",
                True
            )
        }
    
    def _validate_obo_token(self, obo_token, required_scope: str) -> bool:
        """
        Validate OBO token and check permissions
        
        Args:
            obo_token: OBO token to validate
            required_scope: Required permission scope for operation
            
        Returns:
            bool: True if token is valid and has required scope
        """
        if not obo_token.is_valid():
            self._log_access("DENIED", "Token expired", obo_token)
            logger.warning(f" Token expired for {obo_token.original_user_id}")
            return False
        
        # Check if token has required scope
        has_scope = (
            required_scope in obo_token.scopes or 
            "github:*" in obo_token.scopes
        )
        
        if not has_scope:
            self._log_access("DENIED", f"Missing scope: {required_scope}", obo_token)
            logger.warning(
                f" Permission denied: {obo_token.original_user_id} "
                f"lacks scope '{required_scope}'"
            )
            return False
        
        return True
    
    def _log_access(self, status: str, operation: str, obo_token, details: str = ""):
        """
        Log all access attempts with full identity chain
        
        Args:
            status: Operation status (ALLOWED/DENIED)
            operation: Operation name
            obo_token: OBO token containing identity information
            details: Additional details about the operation
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "operation": operation,
            "user": obo_token.original_user_id,
            "role": obo_token.original_role.value,
            "identity_chain": " → ".join(obo_token.identity_chain),
            "details": details
        }
        self.audit_log.append(log_entry)
        
        status_icon = "Allowed" if status == "ALLOWED" else "Denied"
        logger.info(
            f"{status_icon} {status}: {operation} | "
            f"User: {obo_token.original_user_id} | "
            f"Chain: {log_entry['identity_chain']}"
        )
        
        if details:
            logger.debug(f"   Details: {details}")
    
    # -----------------------------
    # FINAL PATCHED VERSION (ONLY)
    # -----------------------------
    def list_repositories(self, obo_token) -> Dict[str, Any]:
        """
        List repositories accessible to user
        
        Filters repositories based on:
        - Public repositories: accessible to all
        - Private repositories: require github:read_private_repos scope
        
        Args:
            obo_token: OBO token with user identity and permissions
            
        Returns:
            Dict with list of accessible repositories or error
        """
        has_public = "github:read_public_repos" in obo_token.scopes or "github:*" in obo_token.scopes
        has_private = "github:read_private_repos" in obo_token.scopes or "github:*" in obo_token.scopes
        
        if not (has_public or has_private):
            return {"error": "Unauthorized - requires read permissions", "repos": []}
        
        # Filter repos based on permissions        
        accessible_repos = []
        user_role = getattr(obo_token.original_role, "value", str(obo_token.original_role)).lower()
         
        for repo_name, repo_data in MockGitHubData.REPOS.items():   
            if "financial-data" in repo_name and user_role != "finance":
                continue 

            if repo_data["visibility"] == "public" and has_public:
                accessible_repos.append({
                    "name": repo_name,
                    "visibility": "public",
                    "description": repo_data.get("description", "")
                })
                
            elif repo_data["visibility"] == "private" and has_private:
                accessible_repos.append({
                    "name": repo_name,
                    "visibility": "private",
                    "description": repo_data.get("description", "")
                })
                      
        self._log_access(
            "ALLOWED", 
            "list_repositories", 
            obo_token, 
            f"Found {len(accessible_repos)} accessible repositories (Role: {user_role})"
        )
        
        return {"repos": accessible_repos, "count": len(accessible_repos)}
    
        ###### old version ######
        # operation = self.operations["list_repositories"]
        
        # if not self._validate_obo_token(obo_token, operation.required_scope):
        #     return {"error": "Unauthorized - missing required permissions", "repos": []}
        
        # # Filter repos based on permissions
        # accessible_repos = []
        # for repo_name, repo_data in MockGitHubData.REPOS.items():
        #     if repo_data["visibility"] == "public":
        #         accessible_repos.append({
        #             "name": repo_name,
        #             "visibility": "public",
        #             "description": repo_data.get("description", "")
        #         })
        #     elif "github:read_private_repos" in obo_token.scopes or "github:*" in obo_token.scopes:
        #         accessible_repos.append({
        #             "name": repo_name,
        #             "visibility": "private",
        #             "description": repo_data.get("description", "")
        #         })
        
        # self._log_access(
        #     "ALLOWED", 
        #     "list_repositories", 
        #     obo_token, 
        #     f"Found {len(accessible_repos)} accessible repositories"
        # )
        
        # return {"repos": accessible_repos, "count": len(accessible_repos)}
    
    def read_file(self, obo_token, repo: str, filename: str) -> Dict[str, Any]:
        """
        Read file from repository
        
        Security checks:
        1. User has github:read_code permission
        2. Repository exists
        3. User has access to private repositories (if applicable)
        4. File exists in repository
        
        Args:
            obo_token: OBO token with user identity
            repo: Repository name (e.g., "private/api-service")
            filename: File to read (e.g., "server.py")
            
        Returns:
            Dict with file contents or error message
        """
        operation = self.operations["read_file"]
        
        # Check basic read permission
        if not self._validate_obo_token(obo_token, operation.required_scope):
            return {"error": "Unauthorized - missing github:read_code permission"}
        
        # Check if repo exists
        if repo not in MockGitHubData.REPOS:
            self._log_access(
                "DENIED", 
                "read_file", 
                obo_token, 
                f"Repository not found: {repo}"
            )
            return {"error": f"Repository '{repo}' not found"}
        
        repo_data = MockGitHubData.REPOS[repo]
        
        # Check private repo access
        if repo_data["visibility"] == "private":
            if not self._validate_obo_token(obo_token, "github:read_private_repos"):
                return {"error": f"Cannot access private repository '{repo}'"}
        
        # Check if file exists
        if filename not in repo_data["files"]:
            self._log_access(
                "DENIED", 
                "read_file", 
                obo_token, 
                f"File not found: {repo}/{filename}"
            )
            return {"error": f"File '{filename}' not found in repository '{repo}'"}
        
        # Simulate file content based on filename
        if filename in ["secrets.env", "sensitive_data.csv", "payroll.db"]:
            content = f""" SENSITIVE DATA - Restricted Access
File: {filename}
Repository: {repo}
Access logged for security audit

[This is simulated sensitive data that would normally require additional authorization]
"""
        elif filename == "README.md":
            content = repo_data.get("readme", f"# {repo}\n\nRepository README file")
        else:
            content = f"""# {filename}
                            Repository: {repo}
                            Last modified: 2024-01-15

                            # This is simulated file content for demonstration
                            # In production, this would contain actual source code

                            def main():
                                print("File content from {repo}/{filename}")
                                
                            if __name__ == "__main__":
                                main()
                            """
        
        self._log_access(
            "ALLOWED", 
            "read_file", 
            obo_token, 
            f"Successfully read {repo}/{filename}"
        )
        
        return {
            "content": content, 
            "repo": repo, 
            "filename": filename,
            "size": len(content),
            "type": "text"
        }
    
    def list_issues(self, obo_token, repo: str) -> Dict[str, Any]:
        """
        List issues in repository
        
        Args:
            obo_token: OBO token with user identity
            repo: Repository name
            
        Returns:
            Dict with list of issues or error
        """
        operation = self.operations["list_issues"]
        
        if not self._validate_obo_token(obo_token, operation.required_scope):
            return {"error": "Unauthorized - missing github:read_issues permission"}
        
        if repo not in MockGitHubData.ISSUES:
            return {"error": f"Repository '{repo}' not found or has no issues", "issues": []}
        
        # Check private repo access
        repo_data = MockGitHubData.REPOS.get(repo, {})
        if repo_data.get("visibility") == "private":
            if not self._validate_obo_token(obo_token, "github:read_private_repos"):
                return {"error": f"Cannot access private repository '{repo}'"}
        
        issues = MockGitHubData.ISSUES[repo]
        
        self._log_access(
            "ALLOWED", 
            "list_issues", 
            obo_token, 
            f"Listed {len(issues)} issues in {repo}"
        )
        
        return {"issues": issues, "count": len(issues), "repo": repo}
    
    def create_issue(self, obo_token, repo: str, title: str) -> Dict[str, Any]:
        """
        Create new issue (write operation)
        
        Args:
            obo_token: OBO token with user identity
            repo: Repository name
            title: Issue title
            
        Returns:
            Dict with created issue or error
        """
        operation = self.operations["create_issue"]
        
        if not self._validate_obo_token(obo_token, operation.required_scope):
            return {"error": "Unauthorized - missing github:write_issues permission (write operation)"}
        
        if repo not in MockGitHubData.REPOS:
            return {"error": f"Repository '{repo}' not found"}
        
        # Check private repo access
        repo_data = MockGitHubData.REPOS.get(repo, {})
        if repo_data.get("visibility") == "private":
            if not self._validate_obo_token(obo_token, "github:read_private_repos"):
                return {"error": f"Cannot access private repository '{repo}'"}
        
        # Simulate issue creation
        new_issue = {
            "id": 999,
            "title": title,
            "created_by": obo_token.original_user_id,
            "labels": [],
            "created_at": datetime.now().isoformat(),
            "state": "open"
        }
        
        self._log_access(
            "ALLOWED", 
            "create_issue", 
            obo_token, 
            f"Created issue in {repo}: '{title}'"
        )
        
        return {
            "issue": new_issue, 
            "message": f"Issue created successfully in {repo}",
            "repo": repo
        }
    
    def create_branch(self, obo_token, repo: str, branch_name: str) -> Dict[str, Any]:
        """
        Create new branch (write operation)
        
        Args:
            obo_token: OBO token with user identity
            repo: Repository name
            branch_name: New branch name
            
        Returns:
            Dict with created branch info or error
        """
        operation = self.operations["create_branch"]
        
        if not self._validate_obo_token(obo_token, operation.required_scope):
            return {"error": "Unauthorized - missing github:create_branch permission"}
        
        if repo not in MockGitHubData.REPOS:
            return {"error": f"Repository '{repo}' not found"}
        
        # Check private repo access
        repo_data = MockGitHubData.REPOS.get(repo, {})
        if repo_data.get("visibility") == "private":
            if not self._validate_obo_token(obo_token, "github:read_private_repos"):
                return {"error": f"Cannot access private repository '{repo}'"}
        
        self._log_access(
            "ALLOWED", 
            "create_branch", 
            obo_token, 
            f"Created branch '{branch_name}' in {repo}"
        )
        
        return {
            "branch": branch_name,
            "repo": repo,
            "created_by": obo_token.original_user_id,
            "message": f"Branch '{branch_name}' created successfully"
        }
    
    def get_audit_log(self) -> List[Dict]:
        """
        Return complete audit log for analysis
        
        Returns:
            List of all logged operations with identity chains
        """
        return self.audit_log
    
    def get_audit_summary(self) -> Dict:
        """
        Get summary statistics of audit log
        
        Returns:
            Dict with audit statistics
        """
        total_operations = len(self.audit_log)
        allowed = sum(1 for entry in self.audit_log if entry["status"] == "ALLOWED")
        denied = sum(1 for entry in self.audit_log if entry["status"] == "DENIED")
        
        operations_count = {}
        for entry in self.audit_log:
            op = entry["operation"]
            operations_count[op] = operations_count.get(op, 0) + 1
        
        return {
            "total_operations": total_operations,
            "allowed": allowed,
            "denied": denied,
            "success_rate": f"{(allowed/total_operations*100):.1f}%" if total_operations > 0 else "N/A",
            "operations_breakdown": operations_count
        }

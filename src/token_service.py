"""
Token Service: Manages user tokens and OBO token exchange
Implements RFC 8693 style On-Behalf-Of token exchange with scope reduction

CHANGES:
- Added ADMIN role with full superuser access (github:*)
- Adjusted DEVELOPER role to have more limited permissions (no admin operations)
- ADMIN has all permissions including delete, admin operations
- DEVELOPER has read/write but not delete/admin operations
"""
import hashlib
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class Role(Enum):
    """User roles with different permission levels"""
    DEVELOPER = "developer"
    FINANCE = "finance"
    MARKETING = "marketing"
    ADMIN = "admin"

@dataclass
class UserToken:
    """User authentication token with role-based permissions"""
    user_id: str
    role: Role
    permissions: List[str]
    issued_at: float
    expires_at: float
    token_id: str
    
    def is_valid(self) -> bool:
        """Check if token is still valid"""
        return time.time() < self.expires_at
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['role'] = self.role.value
        return data

@dataclass
class OBOToken:
    """On-Behalf-Of token maintaining user identity chain"""
    original_user_id: str
    original_role: Role
    acting_service: str
    scopes: List[str]
    issued_at: float
    expires_at: float
    token_id: str
    parent_token_id: str
    identity_chain: List[str]
    
    def is_valid(self) -> bool:
        """Check if OBO token is still valid"""
        return time.time() < self.expires_at
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['original_role'] = self.original_role.value
        return data

class TokenService:
    """
    Manages token issuance and OBO token exchange
    Implements RFC 8693 style token exchange with scope reduction
    """
    
    def __init__(self, token_expiry: int = 3600, obo_expiry: int = 600):
        self.token_expiry = token_expiry
        self.obo_expiry = obo_expiry
        self.issued_tokens: Dict[str, UserToken] = {}
        self.obo_tokens: Dict[str, OBOToken] = {}
        
        # Define role-based permissions (LEAST PRIVILEGE)
        # UPDATED: Admin has full access, Developer has limited access
        self.role_permissions = {
            Role.ADMIN: [
                "github:*",  # Full superuser access to everything
                "github:read_code",
                "github:read_issues",
                "github:write_issues",
                "github:create_branch",
                "github:read_private_repos",
                "github:read_public_repos",
                "github:read_public_issues",
                "github:read_public_repos",
                "github:read_readme"
            ],
            Role.DEVELOPER: [
                "github:read_code",
                "github:read_issues",
                "github:write_issues",
                "github:create_branch",
                "github:read_private_repos"
                # Note: NO delete, NO admin operations, NO wildcard
            ],
            Role.FINANCE: [
                "github:read_public_repos",
                "github:read_public_issues"
            ],
            Role.MARKETING: [
                "github:read_public_repos",
                "github:read_readme"
            ]
        }
    
    def issue_user_token(self, user_id: str, role: Role) -> UserToken:
        """
        Issue initial user authentication token
        
        Args:
            user_id: User identifier (email)
            role: User role determining permissions
            
        Returns:
            UserToken with role-based permissions
        """
        permissions = self.role_permissions.get(role, [])
        
        token_id = hashlib.sha256(
            f"{user_id}_{role.value}_{time.time()}".encode()
        ).hexdigest()[:16]
        
        token = UserToken(
            user_id=user_id,
            role=role,
            permissions=permissions,
            issued_at=time.time(),
            expires_at=time.time() + self.token_expiry,
            token_id=token_id
        )
        
        self.issued_tokens[token_id] = token
        
        logger.info(f"✅ Issued user token: {user_id} ({role.value}) - Token ID: {token_id}")
        
        return token
    
    def exchange_for_obo_token(
        self, 
        user_token: UserToken, 
        target_service: str,
        requested_scopes: List[str]
    ) -> Optional[OBOToken]:
        """
        Exchange user token for OBO token (RFC 8693 style)
        **CRITICAL SECURITY BOUNDARY**: implements scope reduction
        
        Args:
            user_token: Original user token
            target_service: Target service (e.g., 'mcp_github')
            requested_scopes: Scopes requested by agent
            
        Returns:
            OBOToken with reduced scopes, or None if validation fails
        """
        # Step 1: Validate user token
        if not user_token.is_valid():
            logger.warning(f"❌ OBO exchange failed: Token expired for {user_token.user_id}")
            return None
        
        # Step 2: Scope reduction - Only grant scopes user actually has
        granted_scopes = [
            scope for scope in requested_scopes 
            if scope in user_token.permissions or "github:*" in user_token.permissions
        ]
        
        if not granted_scopes:
            logger.warning(
                f"❌ OBO exchange failed: No valid scopes for {user_token.user_id}. "
                f"Requested: {requested_scopes}, User has: {user_token.permissions}"
            )
            return None
        
        # Step 3: Create OBO token with reduced scope
        token_id = hashlib.sha256(
            f"{user_token.user_id}_{target_service}_{time.time()}".encode()
        ).hexdigest()[:16]
        
        obo_token = OBOToken(
            original_user_id=user_token.user_id,
            original_role=user_token.role,
            acting_service=target_service,
            scopes=granted_scopes,
            issued_at=time.time(),
            expires_at=time.time() + self.obo_expiry,  # Shorter than user token
            token_id=token_id,
            parent_token_id=user_token.token_id,
            identity_chain=[user_token.user_id, "ai_agent", target_service]
        )
        
        self.obo_tokens[token_id] = obo_token
        
        logger.info(
            f"✅ OBO token issued: {user_token.user_id} -> {target_service}. "
            f"Granted scopes: {granted_scopes}. "
            f"Identity chain: {' → '.join(obo_token.identity_chain)}"
        )
        
        return obo_token
    
    def validate_obo_token(self, token_id: str) -> Optional[OBOToken]:
        """Validate and retrieve OBO token"""
        token = self.obo_tokens.get(token_id)
        if token and token.is_valid():
            return token
        return None
    
    def get_user_token(self, token_id: str) -> Optional[UserToken]:
        """Retrieve user token by ID"""
        return self.issued_tokens.get(token_id)

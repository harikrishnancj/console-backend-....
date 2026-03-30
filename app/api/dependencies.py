from fastapi import HTTPException, Depends, status, Request
from app.utils.session_resolver import get_session_identity
from app.core.security import verify_token
from app.core.redis import redis_client
import json

SESSION_COOKIE_NAME = "session_id"

def get_current_superadmin(request: Request) -> dict:
    """Verify the caller is an authenticated superadmin via cookie session."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # 1. Lookup Session in Redis
    vault_json = redis_client.get(f"session:{session_id}")
    if not vault_json:
        raise HTTPException(status_code=401, detail="Invalid Session")
        
    # 2. Open Vault
    try:
        vault = json.loads(vault_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=401, detail="Invalid Session Data")

    # 3. Verify Internal Access Token 
    access_token = vault.get("access_token")
    payload = verify_token(access_token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Session Expired")

    if payload.get("type") != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")
        
    return payload


class PermissionChecker:
    def __init__(self, required_permission: str):
        self.required_permission = required_permission

    def __call__(self, identity: dict = Depends(get_session_identity)):
        """
        The actual Bouncer logic.
        identity: The session data retrieved from Redis.
        """
        # If the user is a Tenant, they typically have full access (*)
        if identity.get("type") == "tenant":
            return True
            
        permissions = identity.get("permissions", [])
        
        if self.required_permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {self.required_permission}"
            )
        return True

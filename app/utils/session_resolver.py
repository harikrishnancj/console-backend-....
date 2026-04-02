from fastapi import HTTPException, Request
from app.core.redis import redis_client
from app.core.security import verify_token
import json

SESSION_COOKIE_NAME = "access_token"

async def get_session_identity(request: Request):
    session_jwt = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_jwt:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # 1. Decode JWT to extract the raw session_id
    session_payload = verify_token(session_jwt)
    if not session_payload or session_payload.get("token_type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    
    raw_session_id = session_payload.get("session_id")
    
    # 2. Lookup in Redis using the extracted session_id (async)
    vault_json = await redis_client.get(f"session:{raw_session_id}")
    if not vault_json:
        raise HTTPException(status_code=401, detail="Invalid Session")
        
    # 3. Open Vault
    try:
        vault = json.loads(vault_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=401, detail="Invalid Session Data")
        
    # 4. Extract Identity Information
    tenant_id = vault.get("tenant_id")
    user_id = vault.get("user_id")
    user_type = vault.get("user_type")
    
    # Logic to normalize tenant_id for different roles
    # If the user is a tenant themselves, the user_id is the tenant_id
    if tenant_id is None:
        if user_type == "tenant":
            tenant_id = user_id

    if tenant_id is None:
        raise HTTPException(status_code=401, detail="Tenant identity not found")

    return {
        "tenant_id": int(tenant_id),
        "user_id": int(user_id) if user_id else None,
        "user_type": user_type,
        "session_id": raw_session_id,
        "roles": vault.get("roles", []),
        "permissions": vault.get("permissions", [])
    }
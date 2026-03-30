from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.core.redis import redis_client
from app.models import Tenant, User, Permission, RolePermissionMapping, RoleUserMapping, Role
import uuid
import json
from app.schemas.tenant import TenantValidate
from app.core.security import verify_password, create_access_token, create_refresh_token, verify_token
from app.core.config import REFRESH_TOKEN_EXPIRE_MINUTES
from app.crud import crud4user as crud_user

async def login_service(db: Session, login_data: TenantValidate):
    tenant = db.query(Tenant).filter(Tenant.email == login_data.email).first()
    if tenant and verify_password(login_data.password, tenant.hashed_password):
        claims = {"type": "tenant", "tenant_id": tenant.tenant_id}
        subject = str(tenant.tenant_id)
        token_id = tenant.tenant_id
        
        # 1. Generate Session ID first
        session_id = str(uuid.uuid4())
        
        # 2. Create tokens
        access_token = create_access_token(subject, session_id=session_id, user_type="tenant")
        refresh_token = create_refresh_token(subject, session_id=session_id, user_type="tenant")

        # 3. Store identity in Redis (Vault)
        vault_data = {
            "user_id": token_id, 
            "tenant_id": tenant.tenant_id,
            "user_type": "tenant",
            "refresh_token": refresh_token
        }

        redis_client.set(f"session:{session_id}", json.dumps(vault_data), ex=REFRESH_TOKEN_EXPIRE_MINUTES * 60)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }


    user = crud_user.get_user_by_email(db, email=login_data.email)
    if user and verify_password(login_data.password, user.hashed_password):
    
        claims = {"type": "user", "tenant_id": user.tenant_id}
        subject = str(user.user_id)
        token_id = user.user_id 
        
        # 1. Generate Session ID first
        session_id = str(uuid.uuid4())
        
        # 4. Create tokens
        access_token = create_access_token(subject, session_id=session_id, user_type="user")
        refresh_token = create_refresh_token(subject, session_id=session_id, user_type="user")

        # 5. Fetch permissions and roles
        permissions = get_user_permissions(db, user.user_id)
        roles = get_user_roles(db, user.user_id)

        # 6. Store identity and REFRESH TOKEN in Redis
        vault_data = {
            "user_id": token_id, 
            "tenant_id": user.tenant_id,
            "user_type": "user",
            "roles": roles,
            "permissions": permissions,
            "refresh_token": refresh_token
        }
        
        # Store in Redis (Vault)
        await redis_client.set(f"session:{session_id}", json.dumps(vault_data), ex=REFRESH_TOKEN_EXPIRE_MINUTES * 60)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    raise HTTPException(status_code=400, detail="Invalid email or password")

async def logout_service(session_id: str):
    # Just kill the session in Redis
    if session_id:
        await redis_client.delete(f"session:{session_id}")
    return {"msg": "Logged out successfully"}


async def refresh_token_service(session_id: str, refresh_token_from_cookie: str):
    # 1. Lookup Session
    vault_json = await redis_client.get(f"session:{session_id}")
    if not vault_json:
        raise HTTPException(401, "Invalid Session")
        
    try:
        vault = json.loads(vault_json)
    except:
        raise HTTPException(401, "Invalid Session Data")

    # 2. Verify Refresh Token matches Redis
    stored_refresh_token = vault.get("refresh_token")
    if stored_refresh_token != refresh_token_from_cookie:
        # Potential refresh token reuse or theft
        await redis_client.delete(f"session:{session_id}")
        raise HTTPException(401, "Security Alert: Refresh token mismatch. Session revoked.")

    # 3. Verify Token Integrity & Extract Subject
    payload = verify_token(refresh_token_from_cookie)
    if not payload or payload.get("token_type") != "refresh":
         raise HTTPException(401, "Invalid or expired refresh token")

    # 4. Create NEW Access Token
    subject = payload.get("sub")
    user_type = vault.get("user_type")
    
    new_access_token = create_access_token(subject, session_id=session_id, user_type=user_type)
    
    return {
        "access_token": new_access_token
    }

#get-me
def get_me_service(db: Session, identity: dict):
    if identity["user_type"] == "tenant":
        tenant = db.query(Tenant).filter(Tenant.tenant_id == identity["tenant_id"]).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return {
            "user_type": "tenant",
            "user": {
                "name": tenant.name
            }
        }
    
    elif identity["user_type"] == "user":
        user = db.query(User).filter(User.user_id == identity["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "user_type": "user",
            "roles": identity.get("roles", []),
            "permissions": identity.get("permissions", []),
            "user": {
                "id": user.user_id,
                "tenant_id": user.tenant_id,
                "user_name": user.username
            }
        }
    
    raise HTTPException(status_code=401, detail="Invalid session identity type")


def get_user_permissions(db: Session, user_id: int):
    """Fetches all distinct permission names for a user based on their roles."""
    permissions = db.query(Permission.name).distinct().join(
        RolePermissionMapping, Permission.permission_id == RolePermissionMapping.permission_id
    ).join(
        RoleUserMapping, RolePermissionMapping.role_id == RoleUserMapping.role_id
    ).filter(
        RoleUserMapping.user_id == user_id
    ).all()
    
    return [p[0] for p in permissions]


def get_user_roles(db: Session, user_id: int):
    """Fetches all role names for a user."""
    roles = db.query(Role.role_name).join(
        RoleUserMapping, Role.role_id == RoleUserMapping.role_id
    ).filter(
        RoleUserMapping.user_id == user_id
    ).all()
    
    return [r[0] for r in roles]

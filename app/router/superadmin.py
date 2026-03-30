from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from typing import List
from typing import Optional
from app.core.database import get_db
from app.crud import crud4super as superadmin_crud
from app.crud import product as product_crud
from app.schemas.superadmin import SuperAdminCreate, SuperAdminLogin, SuperAdminInDBBase
from app.schemas.tenant import TenantInDBBase
from app.schemas.product import ProductInDBBase, ProductCreate, ProductUpdate
from app.utils.response import wrap_response
from app.schemas.base import BaseResponse
from app.crud import crud4tpm as tenant_product_map_crud
from app.schemas.tenant_product_map import TenantProductMapInDBBase
from app.models import SuperAdmin
from app.core.security import verify_password, create_access_token, create_refresh_token, verify_token
from app.api.dependencies import get_current_superadmin
from app.core.redis import redis_client
from app.crud import crud4permission as permission_crud
from app.schemas.permission import PermissionCreate, PermissionUpdate, PermissionResponse
from app.core.config import SESSION_COOKIE_EXPIRE_MINUTES
import uuid
import json

router = APIRouter()


@router.post("/signup", response_model=BaseResponse[SuperAdminInDBBase])
def superadmin_signup(data: SuperAdminCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = superadmin_crud.create_super_admin(db=db, schema=data)
    return wrap_response(data=result, message="Super admin created successfully")


@router.post("/login")
def superadmin_login(data: SuperAdminLogin, response: Response, db: Session = Depends(get_db)):
    admin = db.query(SuperAdmin).filter(SuperAdmin.email == data.email).first()
    if not admin or not verify_password(data.password, admin.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    claims = {"type": "superadmin"}
    session_id = str(uuid.uuid4())
    access_token = create_access_token(subject=str(admin.super_admin_id), session_id=session_id, claims=claims)
    refresh_token = create_refresh_token(subject=str(admin.super_admin_id), session_id=session_id, claims=claims)
    
    vault_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": admin.super_admin_id,
        "type": "superadmin"
    }

    # Store in Redis (Vault)
    redis_client.set(f"session:{session_id}", json.dumps(vault_data), ex=SESSION_COOKIE_EXPIRE_MINUTES * 60)

    # Set session_id in HTTP-only cookie
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=SESSION_COOKIE_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=False,  # Set True in production (HTTPS)
        samesite="lax",
        path="/",
    )

    # Return only visible data (NO session_id!)
    return wrap_response(
        data={
            "type": "superadmin",
            "user": {
                "id": admin.super_admin_id,
                "name": admin.name
            }
        },
        message="Login successful"
    )

@router.post("/logout")
def superadmin_logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")
    redis_client.delete(f"session:{session_id}")
    response.delete_cookie(key="session_id", path="/")
    return wrap_response(data={"msg": "Logged out successfully"}, message="Logout successful")


@router.post("/refresh-token")
def superadmin_refresh_token(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")
    
    # 1. Lookup Session
    vault_json = redis_client.get(f"session:{session_id}")
    if not vault_json:
        raise HTTPException(401, "Invalid Session")
        
    try:
        vault = json.loads(vault_json)
    except:
        raise HTTPException(401, "Invalid Session Data")

    # 2. Get Internal Refresh Token
    refresh_token = vault.get("refresh_token")
    if not refresh_token:
        raise HTTPException(401, "No refresh token in vault")

    # 3. Verify Internal Refresh Token
    payload = verify_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(401, "Session Expired (Internal Token)")
    
    if payload.get("type") != "superadmin":
        raise HTTPException(403, "Not a superadmin token")

    subject = str(payload["sub"])
    claims = {"type": "superadmin"}
    
    # 5. Mint NEW Tokens (Re-use same session_id)
    new_access_token = create_access_token(subject, session_id=session_id, claims=claims)
    new_refresh_token = create_refresh_token(subject, session_id=session_id, claims=claims)
    
    # 6. Update Vault
    vault["access_token"] = new_access_token
    vault["refresh_token"] = new_refresh_token
    
    # Save back to Redis (Reset TTL)
    redis_client.set(f"session:{session_id}", json.dumps(vault), ex=REFRESH_TOKEN_EXPIRE_MINUTES * 60)
    
    return wrap_response(
        data={
            "session_id": session_id,
            "token_type": "bearer",
            "success": True
        },
        message="Token refreshed successfully"
    )
@router.get("/products", response_model=BaseResponse[List[ProductInDBBase]])
def get_products(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = superadmin_crud.get_products(db=db)
    return wrap_response(data=result, message="Products retrieved successfully")

@router.post("/products", response_model=BaseResponse[ProductInDBBase])
def create_product(product: ProductCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = product_crud.create_product(schema=product, db=db)
    return wrap_response(data=result, message="Product created successfully")

@router.put("/products/{product_id}", response_model=BaseResponse[ProductInDBBase])
def update_product(product_id: int, product: ProductUpdate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = product_crud.update_product(schema=product, db=db, product_id=product_id)
    if not result:
        raise HTTPException(status_code=404, detail="Product not found")
    return wrap_response(data=result, message="Product updated successfully")

@router.delete("/products/{product_id}", response_model=BaseResponse[ProductInDBBase])
def delete_product(product_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = product_crud.delete_product(db=db, product_id=product_id)
    if not result:
        raise HTTPException(status_code=404, detail="Product not found")
    return wrap_response(data=result, message="Product deleted successfully")

@router.put("/superadmin/{super_admin_id}", response_model=BaseResponse[SuperAdminInDBBase])
def update_super_admin(super_admin_id: int, super_admin: SuperAdminCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = superadmin_crud.update_super_admin(db=db, super_admin_id=super_admin_id, super_admin=super_admin)
    if not result:
        raise HTTPException(status_code=404, detail="Super admin not found")
    return wrap_response(data=result, message="Super admin updated successfully")

@router.delete("/superadmin/{super_admin_id}", response_model=BaseResponse[SuperAdminInDBBase])
def delete_super_admin(super_admin_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = superadmin_crud.delete_super_admin(db=db, super_admin_id=super_admin_id)
    if not result:
        raise HTTPException(status_code=404, detail="Super admin not found")
    return wrap_response(data=result, message="Super admin deleted successfully")

@router.get("/tenants", response_model=BaseResponse[List[TenantInDBBase]])
def get_all_tenant(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = superadmin_crud.get_all_tenant(db=db)
    return wrap_response(data=result, message="Tenants fetched successfully")

@router.get("/tenantproductmappings", response_model=BaseResponse[List[TenantProductMapInDBBase]])
def get_all_tenant_product_mapping(tenant_id: Optional[int] = None, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = superadmin_crud.get_product_mappings_for_a_tenant(db=db, tenant_id=tenant_id)
    return wrap_response(data=result, message="Tenant product mappings fetched successfully")

@router.get("/product-requests", response_model=BaseResponse[List[TenantProductMapInDBBase]])
def get_pending_requests(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = tenant_product_map_crud.get_pending_requests(db=db)
    return wrap_response(data=result, message="Pending requests fetched successfully")

@router.post("/approve-product/{request_id}", response_model=BaseResponse[TenantProductMapInDBBase])
def approve_product_request(request_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = tenant_product_map_crud.update_request_status(db=db, request_id=request_id, status="APPROVED")
    return wrap_response(data=result, message="Product installed successfully")

@router.post("/reject-product/{request_id}", response_model=BaseResponse[TenantProductMapInDBBase])
def reject_product_request(request_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = tenant_product_map_crud.update_request_status(db=db, request_id=request_id, status="REJECTED")
    return wrap_response(data=result, message="Product status updated to REJECTED")


@router.delete("/tenant-product-mappings/{mapping_id}", response_model=BaseResponse[TenantProductMapInDBBase])
def admin_delete_mapping(mapping_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = tenant_product_map_crud.admin_delete_tenant_product_map(db=db, mapping_id=mapping_id)
    if not result:
        raise HTTPException(status_code=404, detail="Tenant product map not found")
    return wrap_response(data=result, message="Tenant product map deleted successfully by Admin")


@router.post("/tenant-product-mappings", response_model=BaseResponse[TenantProductMapInDBBase])
def admin_create_mapping(tenant_id: int, product_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = tenant_product_map_crud.admin_create_tenant_product_map(db=db, tenant_id=tenant_id, product_id=product_id, status="APPROVED")
    return wrap_response(data=result, message="Product assigned to tenant successfully by Admin")


@router.post("/permissions", response_model=BaseResponse[PermissionResponse])
def create_permission(permission: PermissionCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = permission_crud.create_permission(db=db, permission=permission)
    return wrap_response(data=result, message="Permission created successfully")

@router.get("/permissions", response_model=BaseResponse[List[PermissionResponse]])
def get_permissions(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = permission_crud.get_all_permissions(db=db)
    return wrap_response(data=result, message="Permissions retrieved successfully")

@router.put("/permissions/{permission_id}", response_model=BaseResponse[PermissionResponse])
def update_permission(permission_id: int, permission: PermissionUpdate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = permission_crud.update_permission(db=db, permission_id=permission_id, permission=permission)
    if not result:
        raise HTTPException(status_code=404, detail="Permission not found")
    return wrap_response(data=result, message="Permission updated successfully")

@router.delete("/permissions/{permission_id}", response_model=BaseResponse[PermissionResponse])
def delete_permission(permission_id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_superadmin)):
    result = permission_crud.delete_permission(db=db, permission_id=permission_id)
    if not result:
        raise HTTPException(status_code=404, detail="Permission not found")
    return wrap_response(data=result, message="Permission deleted successfully")

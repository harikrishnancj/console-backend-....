from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.utils.session_resolver import get_session_identity
from app.crud import crud4tent as user_crud
from app.schemas.user import UserInDBBase, UserCreate, UserWithRoles
from app.crud import crud4role as role_crud
from app.schemas.role import RoleInDBBase, RoleCreate, RoleUpdate, RoleUserCount
from app.crud import crud4tpm as tenant_product_map_crud
from app.schemas.tenant_product_map import TenantProductMapInDBBase, TenantProductMapCreate, TenantProductMapWithDetails, TenantProductMappingSpecific
from app.schemas.tenant import Tenantpassupdate,TenantInDBBase
from app.crud import crud4rum as role_user_mapping_crud
from app.schemas.role_user_mapping import RoleUserMappingInDBBase, RoleUserMappingCreate
from app.crud import crud4arm as app_role_mapping_crud
from app.schemas.app_role_mapping import AppRoleMappingInDBBase, AppRoleMappingCreate
from app.crud import product as product_crud
from app.schemas.product import ProductInDBBase
from app.crud import crud4prm as permission_role_mapping_crud
from app.schemas.permission_role_mapping import PermissionRoleMappingCreate, PermissionRoleMappingResponse, PermissionRoleMappingUpdate
from app.schemas.permission import PermissionResponse
from app.schemas.base import BaseResponse
from app.utils.response import wrap_response
from app.crud import crud4permission as permission_crud

router = APIRouter()

@router.post("/users", response_model=BaseResponse[UserInDBBase])
def create_user(user: UserCreate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = user_crud.create_user(db=db, user=user, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="User created successfully")

@router.get("/users", response_model=BaseResponse[List[UserWithRoles]])
def read_users(
    name: Optional[str] = None,  # Filter by username
    email: Optional[str] = None,  # Filter by email
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):
    result = user_crud.get_all_users(db=db, tenant_id=auth["tenant_id"], name=name, email=email)
    return wrap_response(data=result, message="Users fetched successfully")

@router.get("/users/search", response_model=BaseResponse[List[UserWithRoles]])
def search_users(
    q: str,
    limit: int = 10,
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db),
):
    if not q.strip():
        raise HTTPException(status_code=400, detail="Search query 'q' must not be empty")
    result = user_crud.search_users(db=db, tenant_id=auth["tenant_id"], q=q.strip(), limit=limit)
    return wrap_response(data=result, message="User search results fetched successfully")

@router.get("/users/{user_id}", response_model=BaseResponse[UserInDBBase])
def read_user(user_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    db_user = user_crud.get_user_by_id(db=db, user_id=user_id, tenant_id=auth["tenant_id"])
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return wrap_response(data=db_user, message="User details fetched successfully")

@router.delete("/users/{user_id}", response_model=BaseResponse[UserInDBBase])
def delete_user(user_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = user_crud.delete_user(db=db, user_id=user_id, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="User deleted successfully")


@router.get("/roles", response_model=BaseResponse[List[RoleInDBBase]])
def read_roles(
    role_name: Optional[str] = None,  # Filter by role name
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):
    result = role_crud.get_all_roles(db=db, tenant_id=auth["tenant_id"], role_name=role_name)
    return wrap_response(data=result, message="Roles fetched successfully")

@router.get("/roles/{role_id}", response_model=BaseResponse[RoleInDBBase])
def read_role(role_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    db_role = role_crud.get_role_by_id(db=db, role_id=role_id, tenant_id=auth["tenant_id"])
    if db_role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return wrap_response(data=db_role, message="Role details fetched successfully")

@router.post("/roles", response_model=BaseResponse[RoleInDBBase])
def create_role(role: RoleCreate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_crud.create_role(db=db, role=role, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Role created successfully")

@router.put("/roles/{role_id}", response_model=BaseResponse[RoleInDBBase])
def update_role(role_id: int, role: RoleUpdate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_crud.update_role(db=db, role=role, role_id=role_id, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="Role not found")
    return wrap_response(data=result, message="Role updated successfully")

@router.delete("/roles/{role_id}", response_model=BaseResponse[RoleInDBBase])
def delete_role(role_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_crud.delete_role(db=db, role_id=role_id, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="Role not found")
    return wrap_response(data=result, message="Role deleted successfully")

@router.get("/roles/users", response_model=BaseResponse[List[RoleUserCount]])
def read_roles_user_count(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_crud.get_roles_user_count(db=db, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Roles with user counts fetched successfully")

@router.post("/app_role_mappings", response_model=BaseResponse[AppRoleMappingInDBBase])
def create_app_role_mapping(app_role_mapping: AppRoleMappingCreate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = app_role_mapping_crud.create_app_role_mapping(db=db, app_role_mapping=app_role_mapping, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="App role mapping created successfully")

@router.get("/app_role_mappings", response_model=BaseResponse[List[AppRoleMappingInDBBase]])
def read_app_role_mappings(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = app_role_mapping_crud.get_all_app_role_mappings(db=db, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="App role mappings fetched successfully")

@router.get("/app_role_mappings/{app_role_mapping_id}", response_model=BaseResponse[AppRoleMappingInDBBase])
def read_app_role_mapping(app_role_mapping_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    db_app_role_mapping = app_role_mapping_crud.get_app_role_mapping_by_id(db=db, app_role_mapping_id=app_role_mapping_id, tenant_id=auth["tenant_id"])
    if db_app_role_mapping is None:
        raise HTTPException(status_code=404, detail="App role mapping not found")
    return wrap_response(data=db_app_role_mapping, message="App role mapping details fetched successfully")


@router.delete("/app_role_mappings/{app_role_mapping_id}", response_model=BaseResponse[AppRoleMappingInDBBase])
def delete_app_role_mapping(app_role_mapping_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = app_role_mapping_crud.delete_app_role_mapping(db=db, app_role_mapping_id=app_role_mapping_id, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="App role mapping not found")
    return wrap_response(data=result, message="App role mapping deleted successfully")

@router.post("/role_user_mappings", response_model=BaseResponse[List[RoleUserMappingInDBBase]])
def create_role_user_mapping(role_user_mapping: RoleUserMappingCreate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_user_mapping_crud.create_role_user_mapping(
        db=db, 
        role_user_mapping=role_user_mapping, 
        tenant_id=auth["tenant_id"],
        user_id=role_user_mapping.user_id
    )
    return wrap_response(data=result, message="Role user mapping created successfully")

@router.get("/role_user_mappings", response_model=BaseResponse[List[RoleUserMappingInDBBase]])
def read_role_user_mappings(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_user_mapping_crud.get_all_role_user_mappings(db=db, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Role user mappings fetched successfully")

@router.get("/role_user_mappings/{role_user_mapping_id}", response_model=BaseResponse[RoleUserMappingInDBBase])
def read_role_user_mapping(role_user_mapping_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    db_role_user_mapping = role_user_mapping_crud.get_role_user_mapping_by_id(db=db, role_user_mapping_id=role_user_mapping_id, tenant_id=auth["tenant_id"])
    if db_role_user_mapping is None:
        raise HTTPException(status_code=404, detail="Role user mapping not found")
    return wrap_response(data=db_role_user_mapping, message="Role user mapping details fetched successfully")


@router.delete("/role_user_mappings/{role_user_mapping_id}", response_model=BaseResponse[RoleUserMappingInDBBase])
def delete_role_user_mapping(role_user_mapping_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = role_user_mapping_crud.delete_role_user_mapping(db=db, role_user_mapping_id=role_user_mapping_id, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="Role user mapping not found")
    return wrap_response(data=result, message="Role user mapping deleted successfully")



@router.post("/request-product")
def request_product(
    product_id: int, 
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):
    result = tenant_product_map_crud.request_product_subscription(
        db=db, 
        product_id=product_id, 
        tenant_id=auth["tenant_id"]
    )
    return wrap_response(
        data=result.get("data"), 
        message=result.get("message")
    )

@router.get("/tenant_product_maps", response_model=BaseResponse[List[TenantProductMapWithDetails]])
def read_tenant_product_maps(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = tenant_product_map_crud.get_all_tenant_product_maps(db=db, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Tenant product maps fetched successfully")

@router.get("/tenant_product_maps/{tenant_product_map_id}", response_model=BaseResponse[TenantProductMapInDBBase])
def read_tenant_product_map(tenant_product_map_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    db_tenant_product_map = tenant_product_map_crud.get_tenant_product_map_by_id(db=db, tenant_product_map_id=tenant_product_map_id, tenant_id=auth["tenant_id"])
    if db_tenant_product_map is None:
        raise HTTPException(status_code=404, detail="Tenant product map not found")
    return wrap_response(data=db_tenant_product_map, message="Tenant product map details fetched successfully")

@router.get("/tenant_product_mapping", response_model=BaseResponse[List[TenantProductMappingSpecific]])
def get_tenant_product_mapping_specific(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = tenant_product_map_crud.get_specific_tenant_product_mapping(db=db, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Tenant product mappings fetched successfully")

@router.delete("/tenant_product_maps/{tenant_product_map_id}", response_model=BaseResponse[TenantProductMapInDBBase])
def delete_tenant_productmap(tenant_product_map_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = tenant_product_map_crud.delete_tenant_product_map(db=db, tenant_product_map_id=tenant_product_map_id, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="Tenant product map not found")
    return wrap_response(data=result, message="Tenant product map deleted successfully")

@router.get("/my-products", response_model=BaseResponse[List[ProductInDBBase]])
def get_my_products(
    product_name: Optional[str] = None,
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):
    result = product_crud.get_tenant_products(db=db, tenant_id=auth["tenant_id"], product_name=product_name)
    return wrap_response(data=result, message="Tenant products fetched successfully")


@router.get("/my-products/search", response_model=BaseResponse[List[ProductInDBBase]])
def search_my_products(
    q: str,
    limit: int = 10,
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db),
):
    """Predictive search across the tenant's subscribed products."""
    if not q.strip():
        raise HTTPException(status_code=400, detail="Search query 'q' must not be empty")
    result = product_crud.search_tenant_products(db=db, tenant_id=auth["tenant_id"], q=q.strip(), limit=limit)
    return wrap_response(data=result, message="Product search results fetched successfully")

@router.get("/my-products/{product_id}", response_model=BaseResponse[ProductInDBBase])
def get_my_product(
    product_id: int,
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):
    db_product = product_crud.get_tenant_product_by_id(db=db, tenant_id=auth["tenant_id"], product_id=product_id)
    if db_product is None:
        raise HTTPException(status_code=403, detail="Access denied - product not subscribed")
    
    return wrap_response(data=db_product, message="Product details fetched successfully")

@router.put("/update-tenant",response_model=BaseResponse[TenantInDBBase])
def update_tenant(tenant:Tenantpassupdate,db:Session=Depends(get_db),auth:dict=Depends(get_session_identity)):
    result=user_crud.update_tenant(db,tenant,auth)
    if not result:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return wrap_response(data=result, message="Tenant updated successfully")

@router.post("/permission_role_mappings", response_model=BaseResponse[List[PermissionRoleMappingResponse]])
def create_permission_role_mapping(permission_role_mapping: PermissionRoleMappingCreate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = permission_role_mapping_crud.create_permission_role_mapping(db=db, permission_role_mapping=permission_role_mapping, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Permission role mapping(s) created successfully")

@router.get("/permission_role_mappings", response_model=BaseResponse[List[PermissionRoleMappingResponse]])
def read_permission_role_mappings(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = permission_role_mapping_crud.get_all_permission_role_mappings(db=db, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Permission role mappings fetched successfully")

@router.get("/permission_role_mappings/{permission_role_mapping_id}", response_model=BaseResponse[PermissionRoleMappingResponse])
def read_permission_role_mapping(permission_role_mapping_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    db_permission_role_mapping = permission_role_mapping_crud.get_permission_role_mapping(db=db, mapping_id=permission_role_mapping_id, tenant_id=auth["tenant_id"])
    if db_permission_role_mapping is None:
        raise HTTPException(status_code=404, detail="Permission role mapping not found")
    return wrap_response(data=db_permission_role_mapping, message="Permission role mapping details fetched successfully")

@router.put("/permission_role_mappings/{permission_role_mapping_id}", response_model=BaseResponse[PermissionRoleMappingResponse])
def update_permission_role_mapping(permission_role_mapping_id: int, permission_role_mapping: PermissionRoleMappingUpdate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = permission_role_mapping_crud.update_permission_role_mapping(db=db, mapping_id=permission_role_mapping_id, permission_role_mapping=permission_role_mapping, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="Permission role mapping not found")
    return wrap_response(data=result, message="Permission role mapping updated successfully")

@router.delete("/permission_role_mappings/{permission_role_mapping_id}", response_model=BaseResponse[PermissionRoleMappingResponse])
def delete_permission_role_mapping(permission_role_mapping_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = permission_role_mapping_crud.delete_permission_role_mapping(db=db, mapping_id=permission_role_mapping_id, tenant_id=auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="Permission role mapping not found")
    return wrap_response(data=result, message="Permission role mapping deleted successfully")

@router.get("/roles/{role_id}/permissions", response_model=BaseResponse[List[PermissionResponse]])
def get_permissions_for_role(role_id: int, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = permission_role_mapping_crud.get_permissions_by_role(db=db, role_id=role_id, tenant_id=auth["tenant_id"])
    return wrap_response(data=result, message="Role permissions fetched successfully")


@router.get("/permissions", response_model=BaseResponse[List[PermissionResponse]])
def get_permissions(db: Session = Depends(get_db), auth: dict = Depends(get_session_identity)):
    result = permission_crud.get_all_permissions(db=db)
    return wrap_response(data=result, message="Permissions retrieved successfully")

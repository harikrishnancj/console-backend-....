from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.models import AppRoleMapping, Role
from app.schemas.app_role_mapping import AppRoleMappingCreate,AppRoleMappingInDBBase

from typing import Optional

def create_app_role_mapping(db: Session, app_role_mapping: AppRoleMappingCreate, tenant_id: int):
    # Enforce tenant_id from session
    mapping_data = app_role_mapping.model_dump()
    mapping_data["tenant_id"] = tenant_id
    
    # Verify Role exists in this Tenant
    role = db.query(Role).filter(Role.role_id == mapping_data["role_id"], Role.tenant_id == tenant_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found in this tenant")

    # Find existing mapping for this SPECIFIC PRODUCT AND ROLE combination
    existing_mapping = db.query(AppRoleMapping).filter(
        AppRoleMapping.product_id == mapping_data["product_id"],
        AppRoleMapping.role_id == mapping_data["role_id"],
        AppRoleMapping.tenant_id == tenant_id
    ).first()

    if existing_mapping:
        # If this specific role is already assigned, just return it
        db_app_role_mapping = existing_mapping
    else:
        # Create new record (this allows one product to have multiple roles)
        db_app_role_mapping = AppRoleMapping(**mapping_data)
        db.add(db_app_role_mapping)

    db.commit()
    db.refresh(db_app_role_mapping)
    return db_app_role_mapping


def get_all_app_role_mappings(db: Session, tenant_id: int, product_id: Optional[int] = None, role_id: Optional[int] = None):
    query = db.query(AppRoleMapping, Role.role_name).join(
        Role, AppRoleMapping.role_id == Role.role_id
    ).filter(AppRoleMapping.tenant_id == tenant_id)
    
    if product_id:
        query = query.filter(AppRoleMapping.product_id == product_id)
    if role_id:
        query = query.filter(AppRoleMapping.role_id == role_id)
        
    results = query.all()
    # Post-process to attach role_name to the mapping object
    for mapping, role_name in results:
        mapping.role_name = role_name
    
    return [r[0] for r in results]

def get_app_role_mapping_by_id(db: Session, app_role_mapping_id: int, tenant_id: int):
    result = db.query(AppRoleMapping, Role.role_name).join(
        Role, AppRoleMapping.role_id == Role.role_id
    ).filter(
        AppRoleMapping.id == app_role_mapping_id,
        AppRoleMapping.tenant_id == tenant_id
    ).first()
    
    if result:
        mapping, role_name = result
        mapping.role_name = role_name
        return mapping
    return None


def delete_app_role_mapping(db: Session, app_role_mapping_id: int, tenant_id: int):
    db_app_role_mapping = db.query(AppRoleMapping).filter(
        AppRoleMapping.id == app_role_mapping_id,
        AppRoleMapping.tenant_id == tenant_id
    ).first()
    if db_app_role_mapping is None:
        raise HTTPException(status_code=404, detail="App role mapping not found")
    db.delete(db_app_role_mapping)
    db.commit()
    return db_app_role_mapping

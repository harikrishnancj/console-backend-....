from sqlalchemy.orm import Session, joinedload
from app.models import RolePermissionMapping, Role, Permission
from app.schemas.permission_role_mapping import PermissionRoleMappingCreate, PermissionRoleMappingUpdate
from fastapi import HTTPException
from typing import Optional

def create_permission_role_mapping(db: Session, permission_role_mapping: PermissionRoleMappingCreate, tenant_id: int):

    role = db.query(Role).filter(
        Role.role_id == permission_role_mapping.role_id,
        Role.tenant_id == tenant_id
    ).first()

    if not role:
        raise HTTPException(status_code=403, detail="Role not found or does not belong to this tenant.")

    db_mappings = [
        RolePermissionMapping(
            role_id=permission_role_mapping.role_id,
            permission_id=pid
        )
        for pid in permission_role_mapping.permission_ids
    ]

    db.add_all(db_mappings)
    db.commit()

    return db.query(RolePermissionMapping).options(
        joinedload(RolePermissionMapping.role),
        joinedload(RolePermissionMapping.permission)
    ).filter(
        RolePermissionMapping.role_id == permission_role_mapping.role_id,
        RolePermissionMapping.permission_id.in_(permission_role_mapping.permission_ids)
    ).all()

def get_permission_role_mapping(db: Session, mapping_id: int, tenant_id: int):
    return db.query(RolePermissionMapping).join(Role).options(
        joinedload(RolePermissionMapping.role),
        joinedload(RolePermissionMapping.permission)
    ).filter(RolePermissionMapping.id == mapping_id, Role.tenant_id == tenant_id).first()

def get_all_permission_role_mappings(db: Session, tenant_id: int):
    return db.query(RolePermissionMapping).join(Role).options(
        joinedload(RolePermissionMapping.role),
        joinedload(RolePermissionMapping.permission)
    ).filter(Role.tenant_id == tenant_id).all()

def update_permission_role_mapping(db: Session, mapping_id: int, permission_role_mapping: PermissionRoleMappingUpdate, tenant_id: int):
    db_permission_role_mapping = db.query(RolePermissionMapping).join(Role).filter(
        RolePermissionMapping.id == mapping_id,
        Role.tenant_id == tenant_id
    ).first()
    if not db_permission_role_mapping:
        return None
    for field, value in permission_role_mapping.model_dump(exclude_unset=True).items():
        setattr(db_permission_role_mapping, field, value)
    db.commit()
    db.refresh(db_permission_role_mapping)
    return db_permission_role_mapping

def delete_permission_role_mapping(db: Session, mapping_id: int, tenant_id: int):
    db_permission_role_mapping = db.query(RolePermissionMapping).join(Role).filter(
        RolePermissionMapping.id == mapping_id,
        Role.tenant_id == tenant_id
    ).first()
    if not db_permission_role_mapping:
        return None
    db.delete(db_permission_role_mapping)
    db.commit()
    return db_permission_role_mapping

def get_permissions_by_role(db: Session, role_id: int, tenant_id: int):
    # Verify the role belongs to the tenant
    role = db.query(Role).filter(Role.role_id == role_id, Role.tenant_id == tenant_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found or does not belong to this tenant.")
        
    mappings = db.query(RolePermissionMapping).options(
        joinedload(RolePermissionMapping.permission)
    ).filter(RolePermissionMapping.role_id == role_id).all()
    
    # Extract and return just the Permission objects
    return [mapping.permission for mapping in mappings if mapping.permission]
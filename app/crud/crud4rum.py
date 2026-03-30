from fastapi import HTTPException
from app.models import RoleUserMapping, User, Role
from app.schemas.role_user_mapping import RoleUserMappingCreate
from sqlalchemy.orm import Session
from typing import Optional

def create_role_user_mapping(db: Session, role_user_mapping: RoleUserMappingCreate,user_id: int, tenant_id: int):
    mapping_data = role_user_mapping.model_dump()
    role_ids = mapping_data.pop("role_id")
    
    user = db.query(User).filter(User.user_id == user_id, User.tenant_id == tenant_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found in this tenant")
    
    created_mappings = []
    
    for rid in role_ids:
        role = db.query(Role).filter(Role.role_id == rid, Role.tenant_id == tenant_id).first()
        if not role:
            continue
            
        exists = db.query(RoleUserMapping).filter(
            RoleUserMapping.user_id == user_id,
            RoleUserMapping.tenant_id == tenant_id,
            RoleUserMapping.role_id == rid
        ).first()
        
        if not exists:
            new_map = RoleUserMapping(
                user_id=user_id,
                role_id=rid,
                tenant_id=tenant_id
            )
            db.add(new_map)
            created_mappings.append(new_map)
            
    db.commit()
    
    return created_mappings


def get_role_user_mapping_by_id(db: Session, role_user_mapping_id: int, tenant_id: int):
    return db.query(RoleUserMapping).filter(
        RoleUserMapping.id == role_user_mapping_id,
        RoleUserMapping.tenant_id == tenant_id
    ).first()


def get_all_role_user_mappings(db: Session, tenant_id: int, user_id: Optional[int] = None, role_id: Optional[int] = None):
    query = db.query(RoleUserMapping).filter(RoleUserMapping.tenant_id == tenant_id)
    
    if user_id:
        query = query.filter(RoleUserMapping.user_id == user_id)
    if role_id:
        query = query.filter(RoleUserMapping.role_id == role_id)
    return query.all()




def delete_role_user_mapping(db: Session, role_user_mapping_id: int, tenant_id: int):
    db_role_user_mapping = db.query(RoleUserMapping).filter(
        RoleUserMapping.id == role_user_mapping_id,
        RoleUserMapping.tenant_id == tenant_id
    ).first()
    if not db_role_user_mapping:
        return None
    db.delete(db_role_user_mapping)
    db.commit()
    return db_role_user_mapping

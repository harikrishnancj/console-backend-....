from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models import Role, RoleUserMapping
from app.schemas.role import RoleInDBBase, RoleCreate, RoleUpdate
from fastapi import HTTPException
from typing import Optional, List
from sqlalchemy.exc import IntegrityError


def get_role_by_id(db: Session, role_id: int, tenant_id: int):
    return db.query(Role).filter(Role.role_id == role_id, Role.tenant_id == tenant_id).first()

def get_all_roles(db: Session, tenant_id: int = None, role_name: Optional[str] = None):
    query = db.query(Role)
    if tenant_id:
        query = query.filter(Role.tenant_id == tenant_id)
    
    # Filter by role_name if provided (case-insensitive, partial match)
    if role_name:
        query = query.filter(Role.role_name.ilike(f"%{role_name}%"))
    
    return query.all()

def create_role(db: Session, role: RoleCreate, tenant_id: int):
    role_name = role.role_name.strip().lower()

    db_role = Role(role_name=role_name, tenant_id=tenant_id)

    try:
        db.add(db_role)
        db.commit()
        db.refresh(db_role)
        return db_role
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"Role with name '{role_name}' already exists in this tenant"
        )

def update_role(db: Session, role: RoleUpdate, role_id: int, tenant_id: int):
    db_role = db.query(Role).filter(Role.role_id == role_id, Role.tenant_id == tenant_id).first()
    if not db_role:
        return None
    update_data = role.model_dump(exclude_unset=True)
    
    # Check if new role name conflicts with existing one in the same tenant
    if "role_name" in update_data:
        update_data["role_name"] = update_data["role_name"].strip().lower()
        if update_data["role_name"] != db_role.role_name:
            existing_role = db.query(Role).filter(Role.role_name == update_data["role_name"], Role.tenant_id == tenant_id).first()
            if existing_role:
                raise HTTPException(status_code=400, detail=f"Role with name '{update_data['role_name']}' already exists")

    for key, value in update_data.items():
        setattr(db_role, key, value)
    db.commit()
    db.refresh(db_role)
    return db_role

def delete_role(db: Session, role_id: int, tenant_id: int):
    db_role = db.query(Role).filter(Role.role_id == role_id, Role.tenant_id == tenant_id).first()
    if not db_role:
        return None
    db.delete(db_role)
    db.commit()
    return db_role

def get_roles_user_count(db: Session, tenant_id: int):
    # This query uses an outer join and group_by to count users per role efficiently in one SQL call
    results = (
        db.query(Role, func.count(RoleUserMapping.user_id).label("user_count"))
        .outerjoin(RoleUserMapping)
        .filter(Role.tenant_id == tenant_id)
        .group_by(Role.role_id)
        .all()
    )
    
    return [
        {
            "role_name": role.role_name,
            "user_count": user_count
        }
        for role, user_count in results
    ]

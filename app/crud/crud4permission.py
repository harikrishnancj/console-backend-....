from sqlalchemy.orm import Session
from app.models import Permission
from app.schemas.permission import PermissionCreate, PermissionUpdate
from fastapi import HTTPException
from typing import Optional


def create_permission(db: Session, permission: PermissionCreate):
    db_permission = Permission(**permission.model_dump())
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

def get_permission(db: Session, permission_id: int):
    return db.query(Permission).filter(Permission.permission_id == permission_id).first()

def get_all_permissions(db: Session):
    return db.query(Permission).all()

def update_permission(db: Session, permission_id: int, permission: PermissionUpdate):
    db_permission = db.query(Permission).filter(Permission.permission_id == permission_id).first()
    if not db_permission:
        return None
    for field, value in permission.model_dump().items():
        setattr(db_permission, field, value)
    db.commit()
    db.refresh(db_permission)
    return db_permission

def delete_permission(db: Session, permission_id: int):
    db_permission = db.query(Permission).filter(Permission.permission_id == permission_id).first()
    if not db_permission:
        return None
    db.delete(db_permission)
    db.commit()
    return db_permission
from app.models import User, RoleUserMapping, Role, Tenant
from app.schemas.user import UserCreate, UserUpdate
from fastapi import HTTPException
from app.core.security import hash_password, verify_password
from sqlalchemy.orm import Session, selectinload, joinedload
from app.schemas.tenant import Tenantpassupdate
from sqlalchemy import or_
from typing import Optional, List, Dict, Any
from sqlalchemy.exc import IntegrityError


def get_user_by_id(db: Session, user_id: int, tenant_id: int):
    return db.query(User).filter(User.user_id == user_id, User.tenant_id == tenant_id).first()

def create_user(db: Session, user: UserCreate, tenant_id: int):
    # Normalize Email (strip spaces and lowercase)
    

    email = user.email.strip().lower()

    # 1. Proactive check against global uniqueness
    if db.query(Tenant).filter(Tenant.email == email).first():
        raise HTTPException(
            status_code=400,
            detail="This email is already registered as a Tenant account"
        )
    
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=400,
            detail="This email is already registered as a User account"
        )

    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username, 
        email=email,
        hashed_password=hashed_password,
        tenant_id=tenant_id,
        is_active=True,
    )

    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"User with email '{email}' is already registered"
        )


def delete_user(db: Session, user_id: int, tenant_id: int):
    user = db.query(User).filter(User.user_id == user_id, User.tenant_id == tenant_id).first()


    if not user:
        return None
    db.delete(user)
    db.commit()
    return user

def get_all_users(db: Session, tenant_id: int, name: Optional[str] = None, email: Optional[str] = None):
    query = (
        db.query(User)
        .options(
            selectinload(User.user_roles)
            .joinedload(RoleUserMapping.role)
        )
        .filter(User.tenant_id == tenant_id)
    )
    
    if name:
        query = query.filter(User.username.ilike(f"%{name}%"))
    
    if email:
        query = query.filter(User.email.ilike(f"%{email}%"))

    users = query.all()

    # Optimized aggregation using list comprehension
    result = []
    for user in users:
        result.append({
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "tenant_id": user.tenant_id,
            # Get unique role names, filtering to ensure we only get roles for THIS tenant
            "roles": list(set([
                mapping.role.role_name 
                for mapping in user.user_roles 
                if mapping.role and mapping.role.tenant_id == tenant_id
            ]))
        })

    return result


def search_users(db: Session, tenant_id: int, q: str, limit: int = 10):
    if not q:
        return []

    search = f"{q.replace('%', '\\%').replace('_', '\\_')}%"

    users = (
        db.query(User)
        .options(
            selectinload(User.user_roles)
            .joinedload(RoleUserMapping.role)
        )
        .filter(
            User.tenant_id == tenant_id,
            or_(
                User.username.ilike(search, escape="\\"),
                User.email.ilike(search, escape="\\"),
            )
        )
        .order_by(User.username.asc())
        .limit(limit)
        .all()
    )

    return [
        {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "tenant_id": user.tenant_id,
            "roles": list({
                m.role.role_name
                for m in user.user_roles
                if m.role and m.role.tenant_id == tenant_id
            }),
        }
        for user in users
    ]

def update_tenant(db: Session, tenant_data: Tenantpassupdate, auth: dict):
    tenant_db = db.query(Tenant).filter(Tenant.tenant_id == auth["tenant_id"]).first()
    if not tenant_db:
        return None
    if not verify_password(tenant_data.old_password, tenant_db.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid old password")
    
    tenant_db.hashed_password = hash_password(tenant_data.new_password)
    db.commit()
    db.refresh(tenant_db)
    return tenant_db
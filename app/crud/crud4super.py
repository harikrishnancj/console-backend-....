from fastapi import HTTPException
from app.models import SuperAdmin, Tenant, TenantProductMapping, Product
from app.schemas.superadmin import SuperAdminCreate
from app.schemas.tenant import TenantInDBBase
from app.schemas.tenant_product_map import TenantProductMapInDBBase
from app.core.security import hash_password
from sqlalchemy.orm import Session
from typing import Optional, List


def create_super_admin(db: Session, schema: SuperAdminCreate):
    existing = db.query(SuperAdmin).filter(SuperAdmin.email == schema.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    db_super_admin = SuperAdmin(
        name=schema.name,
        email=schema.email,
        hashed_password=hash_password(schema.password),
        is_active=True
    )
    db.add(db_super_admin)
    db.commit()
    db.refresh(db_super_admin)
    return db_super_admin


def delete_super_admin(db: Session, super_admin_id: int):
    db_super_admin = db.query(SuperAdmin).filter(SuperAdmin.super_admin_id == super_admin_id).first()
    if db_super_admin is None:
        raise HTTPException(status_code=404, detail="Super admin not found")
    db.delete(db_super_admin)
    db.commit()
    return db_super_admin


def update_super_admin(db: Session, super_admin_id: int, super_admin: SuperAdminCreate):
    db_super_admin = db.query(SuperAdmin).filter(SuperAdmin.super_admin_id == super_admin_id).first()
    if db_super_admin is None:
        raise HTTPException(status_code=404, detail="Super admin not found")
    db_super_admin.name = super_admin.name
    db_super_admin.email = super_admin.email
    db_super_admin.hashed_password = hash_password(super_admin.password)
    db.commit()
    db.refresh(db_super_admin)
    return db_super_admin

def get_all_tenant(db: Session):
    return db.query(Tenant).all()

def get_product_mappings_for_a_tenant(db: Session, tenant_id: Optional[int] = None):
    query = db.query(TenantProductMapping)
    if tenant_id:
        query = query.filter(TenantProductMapping.tenant_id == tenant_id)
    return query.all()

def get_products(db: Session):
    return db.query(Product).all()
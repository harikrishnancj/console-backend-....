from sqlalchemy.orm import Session
from app.models import Product, TenantProductMapping
from app.schemas.product import ProductInDBBase, ProductCreate, ProductUpdate
from fastapi import HTTPException
from typing import Optional, List


def get_all_products(db: Session, product_name: Optional[str] = None):
    query = db.query(Product)
    
    # Filter by product_name if provided (case-insensitive, partial match)
    if product_name:
        query = query.filter(Product.product_name.ilike(f"%{product_name}%"))
    
    return query.all()

def get_product_by_id(db: Session, product_id: int):
    return db.query(Product).filter(Product.product_id == product_id).first()


def get_tenant_products(db: Session, tenant_id: int, product_name: Optional[str] = None):
    """
    Get all products that a tenant has subscribed to via TenantProductMapping.
    Returns products WITH launch_url for authorized access.
    """
    query = db.query(Product).join(
        TenantProductMapping,
        Product.product_id == TenantProductMapping.product_id
    ).filter(
        TenantProductMapping.tenant_id == tenant_id,
        TenantProductMapping.status == "APPROVED"
    )
    
    if product_name:
        query = query.filter(Product.product_name.ilike(f"%{product_name}%"))
    
    return query.all()


def get_tenant_product_by_id(db: Session, tenant_id: int, product_id: int):
    """
    Get a specific product if tenant has access via TenantProductMapping.
    Returns None if tenant doesn't have access.
    """
    return db.query(Product).join(
        TenantProductMapping,
        Product.product_id == TenantProductMapping.product_id
    ).filter(
        TenantProductMapping.tenant_id == tenant_id,
        Product.product_id == product_id,
        TenantProductMapping.status == "APPROVED"
    ).first()


def create_product(schema: ProductCreate, db: Session):
    # Check if product name already exists
    existing_product = db.query(Product).filter(Product.product_name == schema.product_name).first()
    if existing_product:
        raise HTTPException(status_code=400, detail=f"Product with name '{schema.product_name}' already exists")

    product = Product(
        product_name=schema.product_name,
        price=schema.price,
        product_logo=schema.product_logo,
        product_description=schema.product_description,
        launch_url=schema.launch_url,
        sub_mode=schema.sub_mode,
        details=schema.details
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return product

def update_product(schema: ProductUpdate, db: Session, product_id: int):
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        return None
    
    update_data = schema.model_dump(exclude_unset=True)

    # Check for name conflict
    if "product_name" in update_data and update_data["product_name"] != product.product_name:
        existing_product = db.query(Product).filter(Product.product_name == update_data["product_name"]).first()
        if existing_product:
            raise HTTPException(status_code=400, detail=f"Product with name '{update_data['product_name']}' already exists")

    for key, value in update_data.items():
        setattr(product, key, value)

    db.commit()
    db.refresh(product)
    return product

def delete_product(db: Session, product_id: int):
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        return None
    db.delete(product)
    db.commit()
    return product


def search_all_products(db: Session, q: str, limit: int = 10):
    """Predictive search across all marketplace products by name or description."""
    return (
        db.query(Product)
        .filter(Product.product_name.ilike(f"{q}%"))
        .limit(limit)
        .all()
    )


def search_tenant_products(db: Session, tenant_id: int, q: str, limit: int = 10):
    """Predictive search across a tenant's subscribed (APPROVED) products."""
    return (
        db.query(Product)
        .join(TenantProductMapping, Product.product_id == TenantProductMapping.product_id)
        .filter(
            TenantProductMapping.tenant_id == tenant_id,
            TenantProductMapping.status == "APPROVED",
            Product.product_name.ilike(f"{q}%"),
        )
        .limit(limit)
        .all()
    )

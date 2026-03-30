from sqlalchemy.orm import Session
from app.models import TenantProductMapping, Tenant, Product, AppRoleMapping
from fastapi import HTTPException
from app.schemas.tenant_product_map import TenantProductMapInDBBase, TenantProductMapCreate
from typing import Optional


def get_all_tenant_product_maps(db: Session, tenant_id: int, product_id: Optional[int] = None):
    query = db.query(
        TenantProductMapping, 
        Product.product_name,
        Product.details
    ).join(Product, TenantProductMapping.product_id == Product.product_id).filter(TenantProductMapping.tenant_id == tenant_id)
    if product_id:
        query = query.filter(TenantProductMapping.product_id == product_id)
    
    results = query.all()
    return [
        {
            **mapping.__dict__,
            "product_name": product_name,
            "details": details
        }
        for mapping, product_name, details in results
    ]


def get_specific_tenant_product_mapping(db: Session, tenant_id: int):
    # Fetch onlyAPPROVED subscriptions to provide the launch_url safely
    query = db.query(TenantProductMapping, Product).join(
        Product, 
        TenantProductMapping.product_id == Product.product_id
    ).filter(
        TenantProductMapping.tenant_id == tenant_id,
        TenantProductMapping.status == "APPROVED"
    )
    
    results = query.all()
    
    formatted_results = []
    for mapping, product in results:
        formatted_results.append({
            "id": mapping.id,
            "tenant_id": mapping.tenant_id,
            "status": mapping.status, # Pydantic schema will handle "APPROVED" -> "INSTALLED"
            "product_name": product.product_name,
            "price": float(product.price) if product.price is not None else 0.0,
            "product_logo": product.product_logo or "",
            "product_description": product.product_description or "",
            "launch_url": product.launch_url or "",
            "sub_mode": product.sub_mode,
            "product_id": product.product_id
        })
        
    return formatted_results


def get_tenant_product_map_by_id(db: Session, tenant_product_map_id: int, tenant_id: int):
    return db.query(TenantProductMapping).filter(
        TenantProductMapping.id == tenant_product_map_id,
        TenantProductMapping.tenant_id == tenant_id
    ).first()

def create_tenant_product_map(db: Session, tenant_product_map: TenantProductMapCreate, tenant_id: int):
    mapping_data = tenant_product_map.model_dump()
    mapping_data["tenant_id"] = tenant_id
    
    # Check if Product exists
    product = db.query(Product).filter(Product.product_id == mapping_data["product_id"]).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Check for existing mapping
    existing_mapping = db.query(TenantProductMapping).filter(
        TenantProductMapping.tenant_id == tenant_id,
        TenantProductMapping.product_id == mapping_data["product_id"]
    ).first()
    if existing_mapping:
        raise HTTPException(status_code=400, detail="This tenant is already subscribed to this product")

    db_tenant_product_map = TenantProductMapping(**mapping_data)
    db.add(db_tenant_product_map)
    db.commit()
    db.refresh(db_tenant_product_map)
    return db_tenant_product_map



def delete_tenant_product_map(db: Session, tenant_product_map_id: int, tenant_id: int):
    db_tenant_product_map = db.query(TenantProductMapping).filter(
        TenantProductMapping.id == tenant_product_map_id,
        TenantProductMapping.tenant_id == tenant_id
    ).first()
    
    if db_tenant_product_map:
        db.query(AppRoleMapping).filter(
            AppRoleMapping.tenant_id == tenant_id,
            AppRoleMapping.product_id == db_tenant_product_map.product_id
        ).delete()
        
        db.delete(db_tenant_product_map)
        db.commit()
        
    return db_tenant_product_map



def request_product_subscription(db: Session, product_id: int, tenant_id: int):
    # Check if Product exists
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Check for existing mapping (either PENDING or APPROVED)
    existing_mapping = db.query(TenantProductMapping).filter(
        TenantProductMapping.tenant_id == tenant_id,
        TenantProductMapping.product_id == product_id
    ).first()
    
    if existing_mapping:
        return {
            "status": existing_mapping.status,
            "message": f"You have already requested this product. Status: {existing_mapping.status}",
            "data": existing_mapping
        }

    # Create new PENDING request
    new_request = TenantProductMapping(
        tenant_id=tenant_id,
        product_id=product_id,
        status="PENDING"
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)
    
    return {
        "status": "PENDING",
        "message": "Product requested successfully. Waiting for Admin approval.",
        "data": new_request
    }

def get_pending_requests(db: Session):
    return db.query(TenantProductMapping).filter(
        TenantProductMapping.status == "PENDING"
    ).all()

def update_request_status(db: Session, request_id: int, status: str):
    request = db.query(TenantProductMapping).filter(
        TenantProductMapping.id == request_id
    ).first()
    
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
        
    request.status = status
    db.commit()
    db.refresh(request)
    return request


def admin_delete_tenant_product_map(db: Session, mapping_id: int):
    db_tenant_product_map = db.query(TenantProductMapping).filter(
        TenantProductMapping.id == mapping_id
    ).first()
    
    if db_tenant_product_map:
        # Clean up role mappings associated with this product for this tenant
        db.query(AppRoleMapping).filter(
            AppRoleMapping.tenant_id == db_tenant_product_map.tenant_id,
            AppRoleMapping.product_id == db_tenant_product_map.product_id
        ).delete()
        
        db.delete(db_tenant_product_map)
        db.commit()
        
    return db_tenant_product_map


def admin_create_tenant_product_map(db: Session, tenant_id: int, product_id: int, status: str = "APPROVED"):
    # Check if Product exists
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Check for existing mapping
    existing_mapping = db.query(TenantProductMapping).filter(
        TenantProductMapping.tenant_id == tenant_id,
        TenantProductMapping.product_id == product_id
    ).first()
    
    if existing_mapping:
        existing_mapping.status = status
        db.commit()
        db.refresh(existing_mapping)
        return existing_mapping

    db_tenant_product_map = TenantProductMapping(
        tenant_id=tenant_id,
        product_id=product_id,
        status=status
    )
    db.add(db_tenant_product_map)
    db.commit()
    db.refresh(db_tenant_product_map)
    return db_tenant_product_map


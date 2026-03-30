from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.core.redis import redis_client
from app.models import Tenant, User
from app.schemas.tenant import TenantCreate
from app.core.security import hash_password

def signup_tenant_service(db: Session, tenant_data: TenantCreate):
    verification_key = f"verified_email:{tenant_data.email}"
    is_verified = redis_client.get(verification_key)
    
    if not is_verified or is_verified != "true":
        raise HTTPException(
            status_code=400, 
            detail="Email not verified. Please verify your email with OTP first."
        )


    if db.query(Tenant).filter(Tenant.email == tenant_data.email).first():
        raise HTTPException(status_code=400, detail="This email is already registered as a Tenant account")
    
    if db.query(User).filter(User.email == tenant_data.email).first():
        raise HTTPException(status_code=400, detail="This email is already registered as a User account")

    existing_name = db.query(Tenant).filter(Tenant.name == tenant_data.name).first()
    if existing_name:
        raise HTTPException(
            status_code=400, 
            detail=f"Tenant name '{tenant_data.name}' is already taken. Please choose a different name."
        )
    
    hashed_pwd = hash_password(tenant_data.password)
    new_tenant = Tenant(
        name=tenant_data.name,
        email=tenant_data.email,
        hashed_password=hashed_pwd,
        is_active=True,
        is_verified=True
    )

    db.add(new_tenant)
    db.commit()
    db.refresh(new_tenant)

    redis_client.delete(f"verified_email:{tenant_data.email}")

    return new_tenant

from pydantic import BaseModel, EmailStr
from typing import Optional

class TenantBase(BaseModel):
    email: EmailStr
    name: str

class TenantCreate(TenantBase):
    password: str


class TenantUpdate(BaseModel):

    name: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None

class TenantValidate(BaseModel):
  
    email: EmailStr
    password: str

class Tenantpassupdate(BaseModel):
    old_password: str
    new_password: str

class TenantInDBBase(TenantBase):
    tenant_id: int
    is_active: bool
    is_verified: bool

    class Config:
        from_attributes = True


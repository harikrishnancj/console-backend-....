from pydantic import BaseModel, field_validator
from typing import Optional

class TenantProductMapBase(BaseModel):
    product_id: int

class TenantProductMapCreate(TenantProductMapBase):
    pass


class TenantProductMapInDBBase(TenantProductMapBase):
    id: int
    tenant_id: int
    status: str

    @field_validator("status")
    @classmethod
    def format_status(cls, v: str) -> str:
        if v == "APPROVED":
            return "INSTALLED"
        return v

    class Config:
        from_attributes = True

class TenantProductMapWithDetails(TenantProductMapInDBBase):
    product_name: str
    details: Optional[str] = None

class TenantProductMappingSpecific(TenantProductMapInDBBase):
    product_name: str
    price: float
    product_logo: str
    product_description: str
    launch_url: Optional[str] = None
    sub_mode: bool
    product_id: int
    
    class Config:
        from_attributes = True

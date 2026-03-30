from typing import List, Optional
from pydantic import BaseModel

class AppRoleMappingBase(BaseModel):
    product_id: int
    role_id: int


class AppRoleMappingCreate(AppRoleMappingBase):
    pass


class AppRoleMappingInDBBase(AppRoleMappingBase):
    id: int
    tenant_id: int
    role_name: Optional[str] = None

    class Config:
        from_attributes = True

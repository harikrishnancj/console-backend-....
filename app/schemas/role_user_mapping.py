from pydantic import BaseModel
from typing import Optional

class RoleUserMappingBase(BaseModel):
    role_id: int # Database object has single ID
    user_id: int

class RoleUserMappingCreate(BaseModel):
    role_id: list[int] # Input has list of IDs
    user_id: int


class RoleUserMappingInDBBase(RoleUserMappingBase):
    id: int
    tenant_id: int

    class Config:
        from_attributes = True

    
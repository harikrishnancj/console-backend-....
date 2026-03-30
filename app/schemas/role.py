from pydantic import BaseModel
from typing import Optional, List

class RoleBase(BaseModel):
    role_name: str

class RoleCreate(RoleBase):
    pass

class RoleUpdate(RoleBase):
    
    role_name: Optional[str] = None

class RoleInDBBase(RoleBase):
    role_id: int
    tenant_id: int

    class Config:
        from_attributes = True

class RoleUserCount(BaseModel):
    role_name: str
    user_count: int
        


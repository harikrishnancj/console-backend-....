from pydantic import BaseModel
from typing import Optional

class PermissionRoleMappingCreate(BaseModel):
    role_id: int
    permission_ids: list[int]

class PermissionRoleMappingUpdate(BaseModel):
    permission_id: Optional[int] = None
    role_id: Optional[int] = None

class RoleBase(BaseModel):
    role_id: int
    role_name: str
    
    class Config:
        from_attributes = True

class PermissionBase(BaseModel):
    permission_id: int
    name: str  
    
    class Config:
        from_attributes = True

# 2. Add them as nested items to your mapping response schema
class PermissionRoleMappingResponse(BaseModel):
    id: int # matching the model 'RolePermissionMapping.id'
    permission_id: int
    role_id: int
    
    # These will automatically grab mapping.role and mapping.permission
    role: RoleBase
    permission: PermissionBase

    class Config:
        from_attributes = True
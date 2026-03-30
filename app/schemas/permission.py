from pydantic import BaseModel
from typing import Optional

class PermissionCreate(BaseModel):
    name: str
    description: Optional[str] = None

class PermissionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class PermissionResponse(BaseModel):
    permission_id: int
    name: str
    description: Optional[str] = None

    class Config:
        from_attributes = True

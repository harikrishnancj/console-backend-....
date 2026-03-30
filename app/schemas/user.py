from pydantic import BaseModel
from typing import Optional, List


class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    password: Optional[str] = None
    old_password: Optional[str] = None

class UserInDBBase(UserBase):
    user_id: int
    username: str
    email: str
    is_active: bool
    tenant_id: int

    class Config:
        from_attributes = True


class UserWithRoles(UserInDBBase):
    roles: List[str] = []

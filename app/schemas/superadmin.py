from pydantic import BaseModel
from typing import Optional

class SuperAdminCreate(BaseModel):
    name: str
    email: str
    password: str

class SuperAdminLogin(BaseModel):
    email: str
    password: str

class SuperAdminInDBBase(BaseModel):
    super_admin_id: int
    name: str
    email: str
    is_active: bool

    class Config:
        from_attributes = True

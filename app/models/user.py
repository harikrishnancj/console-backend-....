from ..core.database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), index=True)
    email = Column(String(150), unique=True, index=True)
    hashed_password = Column(String(255))
    is_active = Column(Boolean, default=True)
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))

    tenant = relationship("Tenant", back_populates="users")
    user_roles = relationship("RoleUserMapping", back_populates="user", cascade="all, delete-orphan")

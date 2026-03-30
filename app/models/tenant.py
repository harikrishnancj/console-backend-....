from ..core.database import Base
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relationship

class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True)
    is_active = Column(Boolean, default=True)
    email = Column(String(150), unique=True, index=True)
    hashed_password = Column(String(255))
    is_verified = Column(Boolean, default=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    products_link = relationship("TenantProductMapping", back_populates="tenant", cascade="all, delete-orphan")
    roles = relationship("Role", back_populates="tenant", cascade="all, delete-orphan")

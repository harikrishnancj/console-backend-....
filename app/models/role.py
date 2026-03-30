from ..core.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

class Role(Base):
    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(50), index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))

    __table_args__ = (
        UniqueConstraint("role_name", "tenant_id", name="uq_role_tenant"),
    )

    tenant = relationship("Tenant", back_populates="roles")
    role_users = relationship("RoleUserMapping", back_populates="role", cascade="all, delete-orphan")
    app_mappings = relationship("AppRoleMapping", back_populates="role", cascade="all, delete-orphan")
    permissions = relationship("RolePermissionMapping", back_populates="role", cascade="all, delete-orphan")

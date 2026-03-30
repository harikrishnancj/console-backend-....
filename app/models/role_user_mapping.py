from ..core.database import Base
from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

class RoleUserMapping(Base):
    __tablename__ = "role_user_mappings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"))
    role_id = Column(Integer, ForeignKey("roles.role_id"))
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))

    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "tenant_id", name="uq_user_role_tenant"),
    )

    tenant = relationship("Tenant")
    role = relationship("Role", back_populates="role_users")
    user = relationship("User", back_populates="user_roles")

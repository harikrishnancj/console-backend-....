from ..core.database import Base
from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

class AppRoleMapping(Base):
    __tablename__ = "app_role_mappings"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey("products.product_id"))
    role_id = Column(Integer, ForeignKey("roles.role_id"))
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))

    __table_args__ = (
        UniqueConstraint(
            "product_id",
            "role_id",
            "tenant_id",
            name="uq_app_role_tenant"
        ),
    )

    product = relationship("Product", back_populates="app_roles")
    role = relationship("Role", back_populates="app_mappings")
    tenant = relationship("Tenant")

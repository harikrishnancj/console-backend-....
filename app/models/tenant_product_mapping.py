from ..core.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

class TenantProductMapping(Base):
    __tablename__ = "tenant_product_mappings"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))
    product_id = Column(Integer, ForeignKey("products.product_id"))
    status = Column(String(20), default="PENDING")

    __table_args__ = (
        UniqueConstraint("tenant_id", "product_id", name="uq_tenant_product"),
    )

    tenant = relationship("Tenant", back_populates="products_link")
    product = relationship("Product", back_populates="tenant_mappings")

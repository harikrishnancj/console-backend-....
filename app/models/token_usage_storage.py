from ..core.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

class TokenUsageStorage(Base):
    __tablename__ = "token_usage_storage"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    product_id = Column(Integer, ForeignKey("products.product_id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant")
    user = relationship("User")
    product = relationship("Product")

from ..core.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

class ProductSession(Base):
    __tablename__ = "product_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String(1024), unique=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.tenant_id"))
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    product_id = Column(Integer, ForeignKey("products.product_id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    logout_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)


    tenant = relationship("Tenant")
    user = relationship("User")
    product = relationship("Product")

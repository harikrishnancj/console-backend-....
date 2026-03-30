from ..core.database import Base
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relationship

class Product(Base):
    __tablename__ = "products"

    product_id = Column(Integer, primary_key=True, index=True)
    product_name = Column(String(100), unique=True, index=True)
    launch_url = Column(String(255))
    sub_mode = Column(Boolean, default=False)
    product_logo = Column(String(255))
    product_description = Column(String(500))
    price = Column(Integer)
    details = Column(String(1000), nullable=True)

    tenant_mappings = relationship("TenantProductMapping", back_populates="product", cascade="all, delete-orphan")
    app_roles = relationship("AppRoleMapping", back_populates="product", cascade="all, delete-orphan")

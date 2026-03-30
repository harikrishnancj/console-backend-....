from ..core.database import Base
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

class Permission(Base):
    __tablename__ = "permissions"

    permission_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True)
    description = Column(String(255), nullable=True)

    roles = relationship("RolePermissionMapping", back_populates="permission", cascade="all, delete-orphan")

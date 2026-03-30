from ..core.database import Base
from sqlalchemy import Column, Integer, ForeignKey
from sqlalchemy.orm import relationship

class RolePermissionMapping(Base):
    __tablename__ = "role_permission_mappings"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"))
    permission_id = Column(Integer, ForeignKey("permissions.permission_id"))

    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

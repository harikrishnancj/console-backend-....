from ..core.database import Base
from sqlalchemy import Column, Integer, String, Boolean

class SuperAdmin(Base):
    __tablename__ = "super_admins"

    super_admin_id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True)
    email = Column(String(150), unique=True, index=True)
    hashed_password = Column(String(255))
    is_active = Column(Boolean, default=True)

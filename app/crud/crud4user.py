from sqlalchemy.orm import Session
from app.models import User
from app.schemas.user import UserUpdate, UserInDBBase
from app.core.security import hash_password, verify_password
from fastapi import HTTPException


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def update_user(db: Session, user_id: int, user_update: UserUpdate, tenant_id: int):
    db_user = db.query(User).filter(User.user_id == user_id, User.tenant_id == tenant_id).first()
    if not db_user:
        return None
    
    update_data = user_update.model_dump(exclude_unset=True)
    
    if "password" in update_data and update_data["password"]:
        if "old_password" not in update_data or not update_data["old_password"]:
            raise HTTPException(status_code=400, detail="Current password is required to set a new password")
        
        if not verify_password(update_data.pop("old_password"), db_user.hashed_password):
            raise HTTPException(status_code=400, detail="Invalid current password")
            
        update_data["hashed_password"] = hash_password(update_data.pop("password"))
    elif "old_password" in update_data:
        update_data.pop("old_password")
    
    for key, value in update_data.items():
        setattr(db_user, key, value)
    
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user(db: Session, user_id: int, tenant_id: int):
    return db.query(User).filter(User.user_id == user_id, User.tenant_id == tenant_id).first()
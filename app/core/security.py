import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
import bcrypt
from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_MINUTES

def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)

def create_access_token(subject: str, session_id: Optional[str] = None, user_type: str = "user", token_type: str = "access", claims: Dict[str, Any] = {}):
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    payload = {
        "sub": str(subject),
        "jti": jti,
        "token_type": token_type,
        "user_type": user_type,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        **claims  
    }
    
    if session_id:
        payload["session_id"] = session_id
    
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def create_refresh_token(subject: str, session_id: str, user_type: str = "user", claims: Dict[str, Any] = {}):
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    payload = {
        "sub": str(subject),
        "jti": jti,
        "session_id": session_id,
        "token_type": "refresh",
        "user_type": user_type,
        "exp": now + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES),
        **claims
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None or payload.get("jti") is None:
            raise JWTError
        return payload
    except JWTError:
        return None
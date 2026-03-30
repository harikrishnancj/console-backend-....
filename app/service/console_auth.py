import uuid
import json
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.core.redis import redis_client
from app.core.security import create_access_token
from app.models import Product
from app.crud.crud4user_products import check_user_product_access
from app.crud import product as product_crud
from app.core.config import TEMP_TOKEN_EXPIRE_SECONDS



async def check_auth_and_generate_temp_token(db: Session, tenant_id: int, user_id: int, user_type: str, product_id: int, session_id: str = None):
    # 1. Verify access
    if user_id:
        if not check_user_product_access(db, user_id, tenant_id, product_id):
            raise HTTPException(status_code=403, detail="Access denied: You do not have permission to launch this product")
    else:
        if not product_crud.get_tenant_product_by_id(db, tenant_id, product_id):
            raise HTTPException(status_code=403, detail="Access denied: Tenant is not subscribed to this product")

    # 2. Generate random single-use token
    temp_token = str(uuid.uuid4())

    # 3. Store in Redis
    token_data = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "product_id": product_id,
        "user_type": user_type,
        "session_id": session_id
    }
    
    await redis_client.setex(
        f"temp_token:{temp_token}", 
        TEMP_TOKEN_EXPIRE_SECONDS, 
        json.dumps(token_data)
    )

    return temp_token


async def verify_temp_token_and_generate_jwt(db: Session, temp_token: str):
    # 1. Atomically get and delete the token (One-time use)
    try:
        raw_data = await redis_client.getdel(f"temp_token:{temp_token}")
    except AttributeError:
        # Fallback for older Redis versions
        raw_data = await redis_client.get(f"temp_token:{temp_token}")
        if raw_data:
            await redis_client.delete(f"temp_token:{temp_token}")

    if not raw_data:
        raise HTTPException(status_code=400, detail="Token expired, invalid, or already used")
    
    stored = json.loads(raw_data)
    product_id = stored["product_id"]

    # 2. Add product name for the app's convenience
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
         raise HTTPException(status_code=404, detail="Product not found")

    # 3. Build the JWT claims
    user_type = stored["user_type"]
    claims = {
        "role": "user" if stored["user_id"] else "tenant",
        "tenant_id": stored["tenant_id"],
        "user_id": stored["user_id"],
        "product_id": product_id,
        "product_name": product.product_name,
        "session_id": stored.get("session_id")
    }
    
    # 4. Generate the actual signed JWT Session Token
    # Let "sub" be the user_id (or tenant_id if main tenant)
    subject = str(stored["user_id"] if stored["user_id"] else stored["tenant_id"])
    session_token = create_access_token(
        subject=subject, 
        user_type=user_type, 
        token_type="product_session", 
        claims=claims
    )
    
    return session_token

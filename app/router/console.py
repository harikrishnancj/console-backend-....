from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.utils.session_resolver import get_session_identity, SESSION_COOKIE_NAME
from app.utils.response import wrap_response
from app.service import console_auth
from app.schemas.auth import VerifyTokenRequest
from app.models.product import Product
from app.crud.crud4user_products import check_user_product_access
from app.crud import product as product_crud

router = APIRouter()

@router.get("/check-auth")
async def check_console_auth(
    request: Request,
    db: Session = Depends(get_db)
):
    # 1. First: Check if user has a valid console session!
    # We restrict this to 'tenant' or 'user' types (no product_sessions allowed)
    try:
        auth_ctx = await get_session_identity(request, required_user_types=["tenant", "user"])
    except HTTPException as e:
        return wrap_response(
            data={"authenticated": False, "redirect_to": "/login", "reason": e.detail}, 
            message="No valid console session. Please login."
        )

    # 2. Second: Now that they are logged in, validate the Product ID they requested
    product_id_str = request.headers.get("Product-ID")
    if not product_id_str:
        return wrap_response(data={"authenticated": False}, message="Missing Product-ID header")
    
    try:
        product_id = int(product_id_str)
    except ValueError:
         return wrap_response(data={"authenticated": False}, message="Invalid Product-ID format")

    # 3. Third: Session is valid AND Product ID is valid -> Generate temp token
    try:
        temp_token = console_auth.check_auth_and_generate_temp_token(
            db=db,
            tenant_id=auth_ctx["tenant_id"],
            user_id=auth_ctx.get("user_id"),
            type_=auth_ctx["type"],
            product_id=product_id,
            session_id=auth_ctx.get("session_id")
        )
        return wrap_response(
            data={"authenticated": True, "temp_token": temp_token}, 
            message="Session valid, temp token issued"
        )
    except HTTPException as e:
        # Check if the reason was specifically a non-approved mapping
        detail = e.detail
        reason = "access_denied"
        
        # If the error comes from the service, we can translate it
        if "not subscribed" in detail.lower():
            reason = "no_subscription"
        elif "permission" in detail.lower():
            reason = "no_permission"
            
        return wrap_response(
            data={"authenticated": False, "reason": reason, "detail": detail}, 
            message=detail
        )

@router.post("/verify")
async def verify_temp_token(data: VerifyTokenRequest, db: Session = Depends(get_db)):
    session_token = await console_auth.verify_temp_token_and_generate_jwt(db, data.token)
    
    return wrap_response(
        data={"session_token": session_token},
        message="Token verified successfully"
    )

@router.get("/product/{product_id}/launch-url")
async def get_product_launch_url(
    product_id: int,
    db: Session = Depends(get_db),
    auth_ctx: dict = Depends(get_session_identity)
):
    tenant_id = auth_ctx["tenant_id"]
    user_id = auth_ctx.get("user_id")

    if user_id:
        if not check_user_product_access(db, user_id, tenant_id, product_id):
            raise HTTPException(status_code=403, detail="Access denied: You do not have permission to launch this product")
    else:
        if not product_crud.get_tenant_product_by_id(db, tenant_id, product_id):
            raise HTTPException(status_code=403, detail="Access denied: Tenant is not subscribed to this product")
    
    product = db.query(Product).filter(Product.product_id == product_id).first()
    
    if not product:
        return wrap_response(data={"authenticated": True}, message="Product not found")
        
    return wrap_response(
        data={"launch_url": product.launch_url},
        message="Product URL retrieved successfully"
    )

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Tenant, User, SuperAdmin
from app.schemas.tenant import TenantCreate, TenantInDBBase, TenantValidate
from app.utils.session_resolver import get_session_identity
from app.schemas.otp import OTPRequest, OTPVerify
from app.schemas.auth import PasswordResetRequest, PasswordResetConfirm
from app.service import otp as otp_service
from app.service import tenant as tenant_service
from app.service import auth as auth_service
from app.service import password_reset as password_reset_service
from app.utils.response import wrap_response
from app.schemas.base import BaseResponse
from app.core.config import SESSION_COOKIE_EXPIRE_MINUTES, COOKIE_MAX_AGE, REFRESH_MAX_AGE
from app.core.security import verify_token

router = APIRouter()

SESSION_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"

@router.post("/request-otp")
async def request_otp(data: OTPRequest, db: Session = Depends(get_db)):
    
    # Check across all account types
    if db.query(Tenant).filter(Tenant.email == data.email).first():
        raise HTTPException(status_code=400, detail="This email is already registered as a Tenant account")
    
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="This email is already registered as a User account")

    if db.query(SuperAdmin).filter(SuperAdmin.email == data.email).first():
        raise HTTPException(status_code=400, detail="This email is already registered as a Super Admin account")
    result = await otp_service.request_otp_service(data.email)
    return wrap_response(data=result, message="OTP sent to mail")

@router.post("/verify-otp")
def verify_otp(data: OTPVerify):
    result = otp_service.verify_otp_service(data.email, data.otp)
    return wrap_response(data=result, message="OTP verified")

@router.post("/signup", response_model=BaseResponse[TenantInDBBase])
def signup(tenant: TenantCreate, db: Session = Depends(get_db)):
    result = tenant_service.signup_tenant_service(db, tenant)
    return wrap_response(data=result, message="Tenant registered successfully")

@router.post("/login")
async def login(login_data: TenantValidate, response: Response, db: Session = Depends(get_db)):
    result = await auth_service.login_service(db, login_data)
    
    # Set access_token in HTTP-only cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=result["access_token"],
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )
    
    # Set refresh_token in HTTP-only cookie
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=result["refresh_token"],
        max_age=REFRESH_MAX_AGE,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )
    
    return wrap_response(data={"status": "ok"}, message="Login successful")

@router.get("/me")
def get_me(auth_ctx: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = auth_service.get_me_service(db, auth_ctx)
    return wrap_response(data=result, message="Session details retrieved")

@router.post("/logout")
async def logout(request: Request, response: Response):
    access_jwt = request.cookies.get(SESSION_COOKIE_NAME)
    if not access_jwt:
        raise HTTPException(status_code=401, detail="No active session")
    
    # Decode to get real session_id
    payload = verify_token(access_jwt)
    if not payload:
         raise HTTPException(status_code=401, detail="Invalid Session")
    
    session_id = payload.get("session_id")
    result = await auth_service.logout_service(session_id)
    
    # Delete both cookies
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path="/")
    
    return wrap_response(data=result, message="Logout successful")

@router.post("/refresh-token")
async def refresh_token(request: Request, response: Response):
    refresh_jwt = request.cookies.get(REFRESH_COOKIE_NAME)
    if not refresh_jwt:
        raise HTTPException(status_code=401, detail="No refresh token found")
    
    # 1. Decode refresh token to get session_id
    payload = verify_token(refresh_jwt)
    if not payload or payload.get("token_type") != "refresh":
        raise HTTPException(401, "Invalid refresh token")
    
    session_id = payload.get("session_id")
    result = await auth_service.refresh_token_service(session_id, refresh_jwt)
    
    # 2. Set new access_token cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=result["access_token"],
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )
    
    return wrap_response(data={"status": "ok"}, message="Token refreshed successfully")


@router.post("/forgot-password-request")
async def forgot_password_request(data: PasswordResetRequest, db: Session = Depends(get_db)):
    result = await password_reset_service.request_password_reset_service(db, data.email)
    return wrap_response(data=result, message="Password reset request initiated")

@router.post("/reset-password")
def reset_password(data: PasswordResetConfirm, db: Session = Depends(get_db)):
    result = password_reset_service.reset_password_service(db, data.email, data.new_password, data.old_password)
    return wrap_response(data=result, message="Password reset successfully")


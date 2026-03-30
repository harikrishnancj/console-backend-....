from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.router import signup as signup_router
from app.router import tenantpurpose as tenantpurpose_router
from app.router import market as market_router
from app.router import userpurpose as userpurpose_router
from app.router import superadmin as superadmin_router
from app.router import console as console_router
from app.core.database import engine, Base

from .models import SuperAdmin, Tenant, User, Role, RoleUserMapping, Product, TenantProductMapping, AppRoleMapping, TokenUsageStorage, Permission, RolePermissionMapping, ProductSession

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Console API")

@app.get("/")
async def root():
    return {"message": "Welcome to the Console API", "status": "running"}

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "data": None
        }
    )
 
# CORS
origins = [
    "http://localhost:3000", 
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174"
]  # Specific origins required for cookie auth
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(signup_router.router, prefix="/auth", tags=["Authentication"])
app.include_router(tenantpurpose_router.router, tags=["Tenant Management"])
app.include_router(market_router.router, tags=["Marketplace"])
app.include_router(userpurpose_router.router, tags=["User Management"])
app.include_router(console_router.router, prefix="/console", tags=["Console App Protocol"])
app.include_router(superadmin_router.router, prefix="/superadmin", tags=["Super Admin"])

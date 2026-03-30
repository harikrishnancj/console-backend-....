from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.utils.session_resolver import get_session_identity
from app.crud.crud4user import update_user as crud_update_user, get_user as crud_get_user
from app.schemas.user import UserUpdate,UserInDBBase
from app.crud.crud4user_products import (
    get_user_products as crud_get_user_products,
    get_tenant_products_for_user as crud_get_tenant_products,
    get_user_product_by_id as crud_get_user_product_by_id,
)
from app.schemas.product import ProductInDBBase, ProductUserMarketplace
from app.utils.response import wrap_response
from app.schemas.base import BaseResponse
from typing import List

router = APIRouter()


@router.get("/tenant-products", response_model=BaseResponse[List[ProductUserMarketplace]])
def get_tenant_products_endpoint(
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):

    result = crud_get_tenant_products(db, auth["tenant_id"])
    return wrap_response(data=result, message="Tenant products fetched successfully")


@router.get("/user-products", response_model=BaseResponse[List[ProductInDBBase]])
def get_user_products_endpoint(
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):
    
    result = crud_get_user_products(db, auth["user_id"], auth["tenant_id"])
    return wrap_response(data=result, message="User role-assigned products fetched successfully")


@router.get("/user-products/{product_id}", response_model=BaseResponse[ProductInDBBase])
def get_user_product_by_id_endpoint(
    product_id: int,
    auth: dict = Depends(get_session_identity),
    db: Session = Depends(get_db)
):

    result = crud_get_user_product_by_id(db, auth["user_id"], auth["tenant_id"], product_id)
    if not result:
        raise HTTPException(status_code=403, detail="Access denied: This product is not assigned to your role")
    return wrap_response(data=result, message="Product fetched successfully")

@router.put("/update-user",response_model=BaseResponse[UserInDBBase])
def update_user_endpoint(user: UserUpdate, auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = crud_update_user(db, auth["user_id"], user, auth["tenant_id"])
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return wrap_response(data=result, message="User updated successfully")


@router.get("/get-user", response_model=BaseResponse[UserInDBBase])
def get_user_endpoint(auth: dict = Depends(get_session_identity), db: Session = Depends(get_db)):
    result = crud_get_user(db, auth["user_id"], auth["tenant_id"])
    return wrap_response(data=result, message="User details fetched successfully")

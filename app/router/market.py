from app.crud import product as product_crud
from app.core.database import get_db
from app.schemas.product import ProductInDBBase, ProductMarketplace
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.utils.response import wrap_response
from app.schemas.base import BaseResponse


router = APIRouter()

@router.get("/products", response_model=BaseResponse[List[ProductMarketplace]])
def read_products(
    product_name: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Browse all products in marketplace. URLs hidden for security."""
    result = product_crud.get_all_products(db=db, product_name=product_name)
    return wrap_response(data=result, message="Products fetched successfully")

@router.get("/products/search", response_model=BaseResponse[List[ProductMarketplace]])
def search_products(
    q: str,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    """Predictive search across all marketplace products."""
    if not q.strip():
        raise HTTPException(status_code=400, detail="Search query 'q' must not be empty")
    result = product_crud.search_all_products(db=db, q=q.strip(), limit=limit)
    return wrap_response(data=result, message="Marketplace search results fetched successfully")

@router.get("/products/{product_id}", response_model=BaseResponse[ProductMarketplace])
def read_product(product_id: int, db: Session = Depends(get_db)):
    """Get product details for marketplace. URL hidden for security."""
    db_product = product_crud.get_product_by_id(db=db, product_id=product_id)
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return wrap_response(data=db_product, message="Product details fetched successfully")

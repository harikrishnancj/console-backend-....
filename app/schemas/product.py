from pydantic import BaseModel
from typing import Optional

class ProductBase(BaseModel):
    product_name: str
    price: float
    product_logo: str
    product_description: str
    launch_url: str
    sub_mode: bool
    details: Optional[str] = None


class ProductCreate(ProductBase):
    pass

class ProductUpdate(BaseModel):
    product_name: Optional[str] = None
    price: Optional[float] = None
    product_description: Optional[str] = None
    launch_url: Optional[str] = None
    sub_mode: Optional[bool] = None
    product_logo: Optional[str] = None
    details: Optional[str] = None

class ProductUserMarketplace(BaseModel):
    """
    Product schema for marketplace browsing.
    Excludes launch_url to prevent unauthorized access.
    """
    product_id: int
    product_name: str
    product_description: str
    product_logo: str
    
    sub_mode: bool
    details: Optional[str] = None
    
    class Config:
        from_attributes = True

class ProductMarketplace(BaseModel):
    """
    Product schema for marketplace browsing.
    Excludes launch_url to prevent unauthorized access.
    """
    product_id: int
    product_name: str
    product_description: str
    product_logo: str
    price: float
    sub_mode: bool
    details: Optional[str] = None
    
    class Config:
        from_attributes = True

class ProductInDBBase(ProductBase):
    product_id: int

    class Config:
        from_attributes = True
    


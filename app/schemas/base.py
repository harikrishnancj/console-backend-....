from pydantic import BaseModel
from typing import Generic, TypeVar, Optional, Any

T = TypeVar("T")

class BaseResponse(BaseModel, Generic[T]):
    status: str
    message: str
    data: Optional[T] = None

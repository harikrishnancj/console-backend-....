from typing import Any, Optional
from app.schemas.base import BaseResponse

def wrap_response(data: Any = None, message: str = "Success", status: str = "success") -> dict:
    return {
        "status": status,
        "message": message,
        "data": data
    }

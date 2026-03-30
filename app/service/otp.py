from fastapi import HTTPException
from app.core.redis import redis_client
from app.core.config import OTP_EXPIRE_SECONDS, OTP_COOLDOWN_SECONDS, EMAIL_VERIFIED_EXPIRE_SECONDS
from app.utils.otp import generate_otp
from app.utils.email import send_otp_email
from app.utils.email_validator import validate_email_address

async def request_otp_service(email: str):
    email = validate_email_address(email)

    cooldown_key = f"otp_cooldown:{email}"
    if await redis_client.get(cooldown_key):
        raise HTTPException(
            status_code=429, 
            detail="Too many requests. Please wait 60 seconds before requesting another code."
        )
    
    otp = generate_otp(length=6)
    
    await redis_client.setex(f"otp:{email}", OTP_EXPIRE_SECONDS, otp)
    
    try:
        email_sent = await send_otp_email(email, otp)
        
        if not email_sent:
            await redis_client.delete(f"otp:{email}")
            raise HTTPException(
                status_code=500, 
                detail="Failed to send verification email. Please try again."
            )
        
        await redis_client.setex(cooldown_key, OTP_COOLDOWN_SECONDS, "true")
        
        return {
            "message": f"OTP sent to {email}",
            "email": email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await redis_client.delete(f"otp:{email}")
        print(f"Error in request_otp_service: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request"
        )

async def verify_otp_service(email: str, otp: str):
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    if not otp:
        raise HTTPException(status_code=400, detail="OTP code is required")
    
    stored_otp = await redis_client.get(f"otp:{email}")
    
    if not stored_otp:
        raise HTTPException(status_code=400, detail="OTP expired or not found. Please request a new code.")
    
    if stored_otp != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP code")
    
    await redis_client.setex(f"verified_email:{email}", EMAIL_VERIFIED_EXPIRE_SECONDS, "true")
    
    await redis_client.delete(f"otp:{email}")
    
    return {"message": "Email verified successfully", "email": email}

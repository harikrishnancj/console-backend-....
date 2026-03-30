
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./test.db")
SECRET_KEY: str = os.getenv("SECRET_KEY", "your_default_secret_key")
ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", "10080"))  # 7 days
SESSION_COOKIE_EXPIRE_MINUTES: int = int(os.getenv("SESSION_COOKIE_EXPIRE_MINUTES", "10080")) # 7 days
COOKIE_MAX_AGE: int = int(os.getenv("COOKIE_MAX_AGE", "900"))
REFRESH_MAX_AGE: int = int(os.getenv("REFRESH_MAX_AGE", "604800"))

# Redis Configuration
REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))

# Redis TTL Configuration (seconds)
MAGIC_TOKEN_EXPIRE_SECONDS: int = int(os.getenv("MAGIC_TOKEN_EXPIRE_SECONDS", "10"))
TEMP_TOKEN_EXPIRE_SECONDS: int = int(os.getenv("TEMP_TOKEN_EXPIRE_SECONDS", "30"))
OTP_EXPIRE_SECONDS: int = int(os.getenv("OTP_EXPIRE_SECONDS", "300"))
OTP_COOLDOWN_SECONDS: int = int(os.getenv("OTP_COOLDOWN_SECONDS", "60"))
EMAIL_VERIFIED_EXPIRE_SECONDS: int = int(os.getenv("EMAIL_VERIFIED_EXPIRE_SECONDS", "900"))

# Email Configuration (SMTP)
SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "")
SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "Console App")

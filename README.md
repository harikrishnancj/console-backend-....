# Console API

## Seed SuperAdmin

The first superadmin must be seeded directly into the database. After that, the seeded superadmin can log in and create additional superadmins via the protected `/superadmin/signup` endpoint.

```python
# scripts/seed_superadmin.py
from app.core.database import SessionLocal
from app.models.models import SuperAdmin
from app.core.security import hash_password

db = SessionLocal()
admin = SuperAdmin(
    name="Admin",
    email="admin@example.com",
    hashed_password=hash_password("YourStrongPassword123!"),
    is_active=True
)
db.add(admin)
db.commit()
print("First SuperAdmin created!")
db.close()
```'ve synchronized the .env files. To ensure the authentication flow works, these MUST be identical in both files:

1. Security Keys (Critical)
SECRET_KEY: Both must be secret_key (or any identical string). If they don't match, VDocs won't be able to decode the Console's session tokens.
ALGORITHM: Both must be HS256.
2. Redis Configuration
REDIS_HOST: Both must point to the same Redis server (e.g., localhost).
REDIS_PORT: Both must be 6379. VDocs needs to store its sessions in the same place the Console looks them up.
3. Service URLs (VDocs only)
CONSOLE_VERIFY_URL: Must point to your running Console backend (e.g., http://localhost:8000/console/verify).
PRODUCT_ID: Must match the ID assigned to VDocs in the Console's database (currently set to 3).
I have already updated your VDocs .env to match the Console settings. If you change them in one place, remember to update the other!
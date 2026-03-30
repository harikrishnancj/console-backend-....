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
```
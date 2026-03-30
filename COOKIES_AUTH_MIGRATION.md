# Cookie-Based Authentication Migration Summary

This document summarizes the migration from header-based (JWT in body) to secure **HTTP-only cookie-based session management**.

## 🎯 Goal
To enhance security by preventing session hijacking via XSS (Cross-Site Scripting) and simplifying session management on the frontend.

## 🛡️ Security Features Implemented
- **HttpOnly**: The `session_id` cookie is invisible to JavaScript, preventing theft by malicious scripts.
- **Lax SameSite**: Provides protection against CSRF (Cross-Site Request Forgery) attacks.
- **Secure (Optional)**: Can be set to `True` in production for HTTPS-only transmission.
- **Vault Pattern**: Sensitive JWT tokens stay on the server (Redis). Only a random `session_id` is sent to the browser.

## 📂 Files Modified

| File | Change Description |
|---|---|
| `app/main.py` | Updated CORS to allow specific origins and credentials. |
| `app/core/config.py` | Added `SESSION_COOKIE_EXPIRE_MINUTES` to handle cookie TTL. |
| `app/service/auth.py` | Restructured login to separate `session_id` from `visible_data`. |
| `app/router/signup.py` | Implemented `set_cookie` in login and `delete_cookie` in logout. |
| `app/router/superadmin.py` | Migrated SuperAdmin login/logout/refresh to cookies. |
| `app/utils/session_resolver.py` | Updated to read sessions from cookies automatically. |
| `app/api/dependencies.py` | Updated SuperAdmin dependency and removed header parsing. |
| `app/router/getlink.py` | Updated product logout to use cookie-based tokens. |
| `app/schemas/auth.py` | **Cleaned up**: Deleted unused `Token`, `TokenPair`, and `RefreshTokenSchema`. |

## 💻 Frontend Implementation Guide

### 1. Enable Credentials
You **must** enable credentials in your HTTP client so the browser sends the cookie to the backend.

**Axios:**
```javascript
const api = axios.create({
  baseURL: 'http://localhost:8000',
  withCredentials: true,
});
```

**Fetch:**
```javascript
fetch('http://localhost:8000/api', { credentials: 'include' });
```

### 2. Remove Authorization Headers
Stop manually attaching the `Authorization` header. Browsers handle the cookie automatically.

### 3. Session Recovery
Since JS cannot read the cookie, verify session state by calling a protected endpoint (like a profile check) on app load. If it returns `401`, redirect to login.

---
*Migration completed on: 2026-03-10*

# Quick Start - Clerk Authentication Enabled

## ⚡ 30-Second Setup

### For Windows PowerShell:

1. **Set Environment Variables** (copy all at once):
```powershell
$env:CLERK_PUBLISHABLE_KEY="pk_test_aGVhbHRoeS1saW9uZXNzLTMyLmNsZXJrLmFjY291bnRzLmRldiQ"
$env:CLERK_JWKS_URL="https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
$env:CLERK_ALLOWED_ORIGIN="http://localhost:8080"
```

2. **Build & Run**:
```powershell
cd "d:\Harshat\College Project\LEAKFINDER 1"
mvn clean -DskipTests spring-boot:run
```

3. **Open Browser**:
```
http://localhost:8080
```

4. **Login** with your Clerk account and start scanning!

---

## What Changed?

| Component | Status | Details |
|-----------|--------|---------|
| **Frontend (JS)** | ✅ Ready | Clerk getToken() integrated - sends Bearer tokens automatically |
| **Backend Auth** | ✅ Enabled | /api/scan/* endpoints now require authentication |
| **JWT Validation** | ✅ Active | Uses Clerk's JWKS URL (no hardcoded secrets) |
| **Environment Vars** | ✅ Needed | Must be set before starting the app |
| **Scan Logic** | ✅ Unchanged | 100% backward compatible in functionality |

---

## Security Improvements

```
BEFORE (Disabled):
User → No Auth → Backend → Scan

AFTER (Enabled - Current):
User → Clerk Login → getToken() → Bearer Header → 
Backend JWT Validation → Spring Security → Scan
```

✅ Only authenticated users can scan  
✅ Token signature validated via JWKS URL  
✅ No hardcoded credentials in code  
✅ Session tokens automatically managed by Clerk  

---

## Testing the Auth Layer

### ✅ Should Work:
1. Login with Clerk
2. Start a scan → should succeed
3. Check scan history → should show your scans

### ❌ Should Fail (Test Auth):
1. Open browser DevTools (F12)
2. Go to Network tab
3. Attempt to scan while logged out → should see 401/403 error
4. After login → same request should work (200 OK)

---

## File Structure

```
LEAKFINDER/
├── .env                          ← Credentials file (created)
├── CLERK_AUTH_ENABLED.md        ← Full documentation
├── CLERK_SETUP_QUICK.md         ← This file
├── src/main/java/
│   └── com/leakfinder/
│       ├── config/SecurityConfig.java     ← Auth re-enabled ✅
│       ├── security/
│       │   └── ClerkAuthenticationFilter.java  ← Validates tokens ✅
│       └── ScanController.java  ← Untouched (scan logic)
└── src/main/resources/static/
    └── script.js                ← getClerkAuthHeaders() already there ✅
```

---

## Help!

**Q: Getting "CLERK_PUBLISHABLE_KEY not set" error?**  
A: Env variables weren't set before `mvn spring-boot:run`. Set them first in the terminal!

**Q: 401 Unauthorized on every request?**  
A: Either:
- Not logged in (login first)
- Clerk didn't load (check browser console for Clerk errors)
- Token expired (refresh page to get new token)

**Q: Want to test without Clerk?**  
A: Use dev mode - set `localStorage.setItem('dev_token', 'test-token')` in browser console
(This is the fallback mechanism in script.js)

---

## Next Steps

1. ✅ Build & run the app
2. ✅ Test login flow
3. ✅ Test scanning with authentication
4. ✅ Check that unauthenticated requests fail (401)
5. ✅ Deploy to production with real Clerk keys

---

**Environment Variables Summary:**
```
CLERK_PUBLISHABLE_KEY     = pk_test_aGVhbHRoeS1saW9uZXNzLTMyLmNsZXJrLmFjY291bnRzLmRldiQ
CLERK_JWKS_URL           = https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json
CLERK_ALLOWED_ORIGIN    = http://localhost:8080
```

These are embedded in the `.env` file and must be set as environment variables before running!

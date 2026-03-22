# Clerk Authentication Setup Guide for LEAKFINDER

## Your Clerk Configuration

- **Publishable Key**: `pk_test_a_RzLmR1diQ`
- **JWKS URL**: `https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json`
- **API Version**: `2025-11-10`

## Environment Variables Required

You **MUST** set these environment variables before running the application:

### On Windows PowerShell:
```powershell
$env:CLERK_PUBLISHABLE_KEY="pk_test_a_RzLmR1diQ"
$env:CLERK_JWKS_URL="https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
$env:CLERK_ALLOWED_ORIGIN="http://localhost:8080"

# Then run Maven
mvn clean spring-boot:run
```

### On Linux/macOS (bash/zsh):
```bash
export CLERK_PUBLISHABLE_KEY="pk_test_a_RzLmR1diQ"
export CLERK_JWKS_URL="https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
export CLERK_ALLOWED_ORIGIN="http://localhost:8080"

# Then run Maven
mvn clean spring-boot:run
```

### On Git Bash (Windows):
```bash
export CLERK_PUBLISHABLE_KEY="pk_test_a_RzLmR1diQ"
export CLERK_JWKS_URL="https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
export CLERK_ALLOWED_ORIGIN="http://localhost:8080"

mvn clean spring-boot:run
```

## Troubleshooting

### If you see "Error: Unauthorized. Please login again using Clerk":

1. **Check Environment Variables**: Run this in your terminal to verify the variables are set:
   - **PowerShell**: `Get-ChildItem Env:CLERK_*`
   - **bash/zsh**: `env | grep CLERK_`

2. **Check Console Logs**: Look for debug messages like:
   ```
   [ClerkAuthenticationFilter] Attempting to fetch JWKS from: https://...
   [ClerkAuthenticationFilter] Successfully decoded Clerk domain: healthy-lioness-32
   [ClerkAuthenticationFilter] Successfully authenticated user: ...
   ```

3. **If JWKS fetch fails**: The JWKS URL must be accessible. Check:
   ```bash
   # On PowerShell:
   (Invoke-WebRequest "https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json").StatusCode
   
   # On bash/curl:
   curl -I "https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
   ```

4. **Frontend Token Not Sent**: Check browser console (F12) for:
   ```
   Clerk token obtained, length: XXX
   ```
   If this doesn't appear, Clerk.js may not be loaded. Ensure the Clerk script is in your `index.html`.

## How Authentication Works

1. **User logs in via Clerk** on the frontend (index.html)
2. **Frontend gets Clerk session token** via `Clerk.session.getToken()`
3. **Token is sent in Authorization header**: `Authorization: Bearer <token>`
4. **Backend verifies token** using Clerk's JWKS endpoint
5. **Authentication is set in SecurityContext** for Spring Security
6. **Scan endpoints are protected** and require authentication

## Files Modified

- `src/main/java/com/leakfinder/security/ClerkAuthenticationFilter.java` - Now uses env variables
- `src/main/java/com/leakfinder/config/SecurityConfig.java` - Added explicit endpoint protection
- `src/main/java/com/leakfinder/security/JwtAuthenticationEntryPoint.java` - Added debug logging
- `src/main/resources/application.properties` - Added setup instructions

## Testing Authentication

1. Visit: `http://localhost:8080`
2. You should be redirected to login or see user profile (if already logged in)
3. Try to scan a URL
4. If error occurs, check:
   - Browser console (F12) for token messages
   - Server console for `[ClerkAuthenticationFilter]` messages

## Development vs Production

- **Development**: Use `pk_test_*` keys (for testing)
- **Production**: Use `pk_live_*` keys (for live)
- Update `CLERK_PUBLISHABLE_KEY` when switching environments

package com.leakfinder.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ClerkAuthenticationFilter extends OncePerRequestFilter {

    private static final String SESSION_COOKIE_NAME = "__session";
    // We avoid requiring CLERK_SECRET_KEY by using the public JWKS endpoint.
    // Clerk docs: JWKS public key can be obtained from Frontend API URL with "/.well-known/jwks.json".
    private static final String DEFAULT_JWKS_PATH = "/.well-known/jwks.json";

    private final ObjectMapper objectMapper;

    // kid -> public key cache
    private final Map<String, PublicKey> kidToPublicKey = new ConcurrentHashMap<>();
    private volatile boolean jwksLoaded = false;

    private final Clock clock = Clock.systemDefaultZone();
    private final AtomicLong lastCookieDebugLogAtMillis = new AtomicLong(0L);
    private final AtomicLong lastAuthErrorLogAtMillis = new AtomicLong(0L);

    public ClerkAuthenticationFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, jakarta.servlet.FilterChain filterChain)
            throws java.io.IOException, jakarta.servlet.ServletException {

        // Avoid overriding an already-authenticated request
        Authentication current = SecurityContextHolder.getContext().getAuthentication();
        if (current != null && current.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractClerkSessionToken(request);
        if (!StringUtils.hasText(token)) {
            maybeLogCookieDebug(request);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            PublicKey publicKey = resolvePublicKey(token);
            if (publicKey == null) {
                System.err.println("[ClerkAuthenticationFilter] Failed to resolve public key for token");
                filterChain.doFilter(request, response);
                return;
            }

            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();
            validateTimeClaims(claims);
            validateAzpClaim(claims);

            // Clerk session token typically contains user identifiers in claims.
            // We fall back to `sub` if `user_id` doesn't exist.
            String username = claims.get("user_id", String.class);
            if (!StringUtils.hasText(username)) {
                username = claims.getSubject();
            }

            if (!StringUtils.hasText(username)) {
                System.err.println("[ClerkAuthenticationFilter] No username found in token claims");
                filterChain.doFilter(request, response);
                return;
            }

            System.err.println("[ClerkAuthenticationFilter] Successfully authenticated user: " + username);
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(username, null, List.of());
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (JwtException e) {
            System.err.println("[ClerkAuthenticationFilter] JWT validation error: " + e.getMessage());
            e.printStackTrace();
            maybeLogAuthError(request, "jwt_error", e.getMessage());
            // Token invalid/expired. Let security handle the 401.
        } catch (Exception e) {
            System.err.println("[ClerkAuthenticationFilter] Unexpected authentication error: " + e.getMessage());
            e.printStackTrace();
            maybeLogAuthError(request, "clerk_auth_error", e.getMessage());
            // If verification fails, do not authenticate.
        }

        filterChain.doFilter(request, response);
    }

    private String extractClerkSessionToken(HttpServletRequest request) {
        // Cross-origin requests: it can be provided via Authorization header
        String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(auth)) {
            if (auth.startsWith("Bearer ")) {
                String token = auth.substring("Bearer ".length());
                System.err.println("[ClerkAuthenticationFilter] Extracted Bearer token from Authorization header, length: " + token.length());
                return token;
            } else {
                System.err.println("[ClerkAuthenticationFilter] Authorization header present but not Bearer type: " + auth.substring(0, Math.min(20, auth.length())));
            }
        }

        // Same-origin requests: Clerk sends __session cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (SESSION_COOKIE_NAME.equals(c.getName()) && StringUtils.hasText(c.getValue())) {
                    System.err.println("[ClerkAuthenticationFilter] Extracted token from __session cookie, length: " + c.getValue().length());
                    return c.getValue();
                }
            }
        }

        System.err.println("[ClerkAuthenticationFilter] No token found in Authorization header or cookies");
        return null;
    }

    private void maybeLogCookieDebug(HttpServletRequest request) {
        String path = request.getRequestURI();
        boolean relevant = path != null && (path.startsWith("/api/scan") || path.startsWith("/api/scans/history"));
        if (!relevant) return;

        long now = System.currentTimeMillis();
        long prev = lastCookieDebugLogAtMillis.get();
        if (now - prev < 5000) return; // rate limit
        if (!lastCookieDebugLogAtMillis.compareAndSet(prev, now)) return;

        Cookie[] cookies = request.getCookies();
        boolean hasSession = false;
        String cookieNames = "";
        if (cookies != null) {
            StringBuilder sb = new StringBuilder();
            for (Cookie c : cookies) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(c.getName());
                if (SESSION_COOKIE_NAME.equals(c.getName())) {
                    hasSession = true;
                }
            }
            cookieNames = sb.toString();
        }

        System.err.println("[ClerkAuthenticationFilter] Cookie debug for " + path +
                " | __session present=" + hasSession +
                (cookieNames.isEmpty() ? " | cookies=" + "none" : " | cookies=" + cookieNames));
    }

    private void maybeLogAuthError(HttpServletRequest request, String type, String message) {
        String path = request.getRequestURI();
        boolean relevant = path != null && (path.startsWith("/api/scan") || path.startsWith("/api/scans/history"));
        if (!relevant) return;

        long now = System.currentTimeMillis();
        long prev = lastAuthErrorLogAtMillis.get();
        if (now - prev < 5000) return;
        if (!lastAuthErrorLogAtMillis.compareAndSet(prev, now)) return;

        System.err.println("[ClerkAuthenticationFilter] Auth error for " + path +
                " | type=" + type + " | message=" + (message == null ? "null" : message));
    }

    private PublicKey resolvePublicKey(String token) throws Exception {
        ensureJwksLoaded();
        if (kidToPublicKey.isEmpty()) return null;

        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;

        // JWT header is base64url encoded JSON
        byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
        JsonNode header = objectMapper.readTree(headerBytes);
        String kid = header.path("kid").asText(null);

        if (kid != null && kidToPublicKey.containsKey(kid)) {
            return kidToPublicKey.get(kid);
        }

        // Fallback: if kid missing/unmatched, try any key.
        return kidToPublicKey.values().stream().findFirst().orElse(null);
    }

    private void ensureJwksLoaded() throws Exception {
        if (jwksLoaded) return;

        synchronized (this) {
            if (jwksLoaded) return;

            JsonNode jwks;
            try {
                String jwksUrl = getJwksUrl();
                System.err.println("[ClerkAuthenticationFilter] Attempting to fetch JWKS from: " + jwksUrl);
                jwks = fetchJwks(jwksUrl);
            } catch (Exception e) {
                // If JWKS fetch fails, don't authenticate users.
                System.err.println("[ClerkAuthenticationFilter] Failed to fetch Clerk JWKS: " + e.getMessage());
                e.printStackTrace();
                jwksLoaded = true;
                return;
            }

            JsonNode keys = jwks.path("keys");
            if (keys.isArray()) {
                for (JsonNode k : keys) {
                    String kid = k.path("kid").asText(null);
                    String n = k.path("n").asText(null);
                    String e = k.path("e").asText(null);
                    if (!StringUtils.hasText(kid) || !StringUtils.hasText(n) || !StringUtils.hasText(e)) continue;
                    PublicKey pk = rsaPublicKeyFromJwk(n, e);
                    if (pk != null) {
                        kidToPublicKey.put(kid, pk);
                    }
                }
            }

            jwksLoaded = true;
        }
    }

    private JsonNode fetchJwks(String jwksUrl) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(jwksUrl).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestProperty("Accept", "application/json");

        int status = conn.getResponseCode();
        if (status != 200) {
            throw new RuntimeException("Clerk JWKS fetch failed with status: " + status);
        }

        try (InputStream in = conn.getInputStream()) {
            return objectMapper.readTree(in);
        }
    }

    private PublicKey rsaPublicKeyFromJwk(String nBase64Url, String eBase64Url) {
        try {
            byte[] nBytes = Base64.getUrlDecoder().decode(nBase64Url);
            byte[] eBytes = Base64.getUrlDecoder().decode(eBase64Url);

            BigInteger n = new BigInteger(1, nBytes);
            BigInteger e = new BigInteger(1, eBytes);

            RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception ex) {
            return null;
        }
    }

    private String getJwksUrl() {
        // Optional override if you want to configure manually.
        String explicit = System.getenv("CLERK_JWKS_URL");
        if (StringUtils.hasText(explicit)) {
            System.err.println("[ClerkAuthenticationFilter] Using CLERK_JWKS_URL env var: " + explicit);
            return explicit;
        }

        // Support multiple environment variable names used in different setups (Netlify/Next.js vs local env)
        String[] candidateEnvNames = new String[] { "CLERK_PUBLISHABLE_KEY", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", "NEXT_PUBLIC_CLERK_FRONTEND_API" };
        String publishableKey = null;
        String usedEnv = null;
        for (String name : candidateEnvNames) {
            String v = System.getenv(name);
            if (StringUtils.hasText(v)) {
                publishableKey = v;
                usedEnv = name;
                break;
            }
        }

        if (!StringUtils.hasText(publishableKey)) {
            System.err.println("[ClerkAuthenticationFilter] WARNING: No Clerk publishable key environment variable found (checked: CLERK_PUBLISHABLE_KEY, NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY, NEXT_PUBLIC_CLERK_FRONTEND_API). Clerk authentication will fail.");
            throw new IllegalStateException("CLERK publishable key environment variable is required.");
        }
        System.err.println("[ClerkAuthenticationFilter] Using publishable key from env var: " + usedEnv);

        String fapiDomain = decodeClerkFrontendApiDomain(publishableKey);
        if (!StringUtils.hasText(fapiDomain)) {
            System.err.println("[ClerkAuthenticationFilter] ERROR: Unable to decode Clerk Frontend API domain from publishable key.");
            throw new IllegalStateException("Unable to derive Clerk JWKS URL from publishable key. Check CLERK_PUBLISHABLE_KEY format.");
        }
        
        String url = "https://" + fapiDomain + DEFAULT_JWKS_PATH;
        System.err.println("[ClerkAuthenticationFilter] Derived JWKS URL: " + url);
        return url;
    }

    private String decodeClerkFrontendApiDomain(String publishableKey) {
        try {
            if (!StringUtils.hasText(publishableKey)) {
                System.err.println("[ClerkAuthenticationFilter] Publishable key is empty");
                return null;
            }
            int idx = publishableKey.indexOf('_');
            if (idx < 0) {
                System.err.println("[ClerkAuthenticationFilter] Invalid publishable key format (missing underscore): " + publishableKey);
                return null;
            }

            // publishable key format: pk_test_<base64url>
            String b64url = publishableKey.substring(publishableKey.lastIndexOf('_') + 1);
            int mod = b64url.length() % 4;
            if (mod > 0) b64url = b64url + "=".repeat(4 - mod);

            byte[] bytes = Base64.getUrlDecoder().decode(b64url);
            String decoded = new String(bytes, StandardCharsets.UTF_8);

            // decoded looks like: "<domain>$"
            int dollar = decoded.indexOf('$');
            if (dollar >= 0) decoded = decoded.substring(0, dollar);
            String domain = decoded.trim();
            System.err.println("[ClerkAuthenticationFilter] Successfully decoded Clerk domain: " + domain);
            return domain;
        } catch (Exception e) {
            System.err.println("[ClerkAuthenticationFilter] Error decoding publishable key: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private void validateTimeClaims(Claims claims) {
        Date now = Date.from(clock.instant());

        Date exp = claims.getExpiration();
        if (exp != null && exp.before(now)) {
            throw new JwtException("Token expired");
        }

        Date nbf = claims.getNotBefore();
        if (nbf != null && nbf.after(now)) {
            throw new JwtException("Token not active yet");
        }
    }

    private void validateAzpClaim(Claims claims) {
        // Optional protection against CSRF token replay for another origin.
        // We allow either:
        // - no azp claim
        // - azp equals the configured origin
        String azp = claims.get("azp", String.class);
        if (!StringUtils.hasText(azp)) return;

        // Only enforce azp if the user explicitly provides an allowed origin.
        // This avoids breaking local dev where Clerk azp formatting can differ.
        String allowed = System.getenv("CLERK_ALLOWED_ORIGIN");
        if (!StringUtils.hasText(allowed)) return;

        String normalizedAzp = azp.endsWith("/") ? azp.substring(0, azp.length() - 1) : azp;
        String normalizedAllowed = allowed.endsWith("/") ? allowed.substring(0, allowed.length() - 1) : allowed;
        if (!normalizedAzp.equals(normalizedAllowed)) {
            throw new JwtException("Invalid azp claim");
        }
    }
}


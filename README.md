# 🔍 LEAKFINDER

> **Web Vulnerability Scanner** — Scan websites and code files for security vulnerabilities.
>
> Made by **Aizen_Ackerman**

![Java](https://img.shields.io/badge/Java-Spring%20Boot-brightgreen) ![Security](https://img.shields.io/badge/Security-Clerk%20Auth-blue) ![License](https://img.shields.io/badge/License-Educational-orange)

---

## 📖 Overview

LEAKFINDER is a full-stack web vulnerability scanner built with **Spring Boot** (backend) and vanilla HTML/CSS/JS (frontend). It scans websites and uploaded files for common security vulnerabilities and presents results in a clean, modern UI with a dynamic universe star field.

---

## ✨ Features

- 🌐 **URL Scanning** — Crawl a website and detect security issues
- 📂 **File Scanning** — Upload any file (source code, config, etc.) and scan for secrets/vulnerabilities
- 🔐 **Authentication** — Clerk-based login with local admin fallback
- 🌌 **Universe UI** — Animated canvas star field with shooting stars
- 📊 **Scan History** — Per-user scan history stored in H2 in-memory database

### Vulnerability Checks

| Category | Checks |
|----------|--------|
| Credentials | Hardcoded passwords, API keys, secrets |
| Injection | SQL injection, XSS patterns |
| Cryptography | Insecure algorithms, weak hashing |
| Headers | Missing security headers, CORS misconfig |
| Transport | SSL/TLS issues, mixed content |
| Dependencies | Outdated/insecure libraries |
| Exposure | Sensitive data disclosure, info leakage |
| Cookies | Missing Secure/HttpOnly flags |

---

## 🏗️ Project Structure

```
LEAKFINDER/
├── src/
│   └── main/
│       ├── java/com/leakfinder/
│       │   ├── LeakfinderEnterpriseApplication.java  # Spring Boot entry point
│       │   ├── ApiServer.java                        # Standalone HTTP server (port 8080)
│       │   ├── VulnScanner.java                      # Core scan engine
│       │   ├── ScanController.java                   # REST scan endpoints
│       │   ├── AuthController.java                   # Local auth (login/JWT)
│       │   ├── config/
│       │   │   └── SecurityConfig.java               # Spring Security config
│       │   └── security/
│       │       ├── ClerkAuthenticationFilter.java    # Clerk JWT validation
│       │       └── JwtAuthenticationFilter.java      # Local JWT validation
│       └── resources/
│           ├── application.properties                # App config (H2 DB, JWT, port)
│           └── static/
│               ├── index.html                        # Main scanner UI
│               ├── login.html                        # Clerk login page
│               ├── script.js                         # Frontend scan logic
│               ├── universe.js                       # Canvas star animation
│               └── style.css                         # Dark theme styles
├── pom.xml                                           # Maven dependencies
└── .env                                              # Clerk keys (not committed)
```

---

## ⚙️ Prerequisites

| Requirement | Version |
|-------------|---------|
| Java JDK | 17+ |
| Maven | 3.6+ |
| Git | Any |
| Browser | Chrome / Firefox / Edge |

---

## 🚀 Running the Application

### 1. Clone the repository

```bash
git clone https://github.com/aizen-ackerman/LEAKFINDER.git
cd LEAKFINDER
```

### 2. Set environment variables

**Windows (PowerShell):**
```powershell
$env:CLERK_JWKS_URL    = "https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
$env:CLERK_ALLOWED_ORIGIN = "http://localhost:8080"
```

**macOS / Linux (bash/zsh):**
```bash
export CLERK_JWKS_URL="https://healthy-lioness-32.clerk.accounts.dev/.well-known/jwks.json"
export CLERK_ALLOWED_ORIGIN="http://localhost:8080"
```

> These are already hard-coded in `application.properties` for local dev — the env vars are optional.

### 3. Build and run

```powershell
mvn spring-boot:run
```

Or compile first then run:
```powershell
mvn clean compile
mvn spring-boot:run
```

### 4. Open the app

Navigate to **[http://localhost:8080](http://localhost:8080)** in your browser.

---

## 🔐 Login

The login page loads the **Clerk sign-in widget** (requires internet). If Clerk is unavailable, a local fallback form is shown automatically.

### Default Local Credentials

| Username | Password |
|----------|----------|
| `admin`  | `admin123` |

> The `admin` user is seeded automatically on startup via `UserSeeder.java`.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Local login → returns JWT token |
| `POST` | `/api/scan/url` | Scan a website URL |
| `POST` | `/api/upload/scan` | Upload & scan a file (base64) |
| `GET`  | `/api/scan/history` | Get scan history for current user |
| `GET`  | `/h2-console` | H2 database console (dev only) |

### Example: Scan a URL

```bash
curl -X POST http://localhost:8080/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Example: Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

---

## 🗄️ Database

Uses **H2 in-memory database** (no setup needed). Data resets on every restart.

- Console: [http://localhost:8080/h2-console](http://localhost:8080/h2-console)
- JDBC URL: `jdbc:h2:mem:leakfinderdb`
- Username: `sa` | Password: *(empty)*

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Spring Boot 3, Spring Security, Spring Data JPA |
| Database | H2 (in-memory) |
| Auth | Clerk (JWT) + local JWT fallback |
| Frontend | HTML5, CSS3, Vanilla JS |
| Animation | HTML Canvas API |
| Build | Maven |

---

## ⚠️ Disclaimer

> LEAKFINDER is intended for **educational and authorized testing purposes only**.
> Always ensure you have explicit permission before scanning any website or system.
> Do not use this tool against systems you do not own or have authorization to test.

---

*Made with ❤️ by Aizen_Ackerman*

# LEAKFINDER

LEAKFINDER is a Web Vulnerability Scanner that identifies security vulnerabilities in websites and code files.

## Features

- **URL Scanning**: Scan websites for security vulnerabilities
- **File Scanning**: Scan local files for security issues
- **Multiple Checks**: 
  - Hardcoded credentials
  - SQL injection patterns
  - XSS vulnerabilities
  - Insecure dependencies
  - Sensitive data exposure
  - Insecure cryptography
  - Outdated libraries
  - CORS misconfigurations
  - SSL/TLS security
  - Security headers
  - Cookie security
  - Mixed content
  - Information disclosure

## Setup

### Prerequisites
- Java JDK 8 or higher

### Running the Application

1. **Compile the Java files:**
   ```bash
   javac *.java
   ```

2. **Start the API server:**
   ```bash
   java ApiServer
   ```

3. **Open your browser:**
   Navigate to `http://localhost:8080`

4. **Start scanning:**
   - Enter a URL (e.g., `example.com`) and click "Scan" to scan a website
   - Or switch to "Scan File" tab and enter a file path to scan a local file

## Usage

### Web Interface

The web interface provides a modern, dark-themed UI where you can:
- Switch between URL and File scanning modes
- View scan results with detailed vulnerability information
- See summary statistics including severity breakdowns
- Review individual check results with issue details

### Command Line (Original)

You can still use the original command-line interface:

```bash
java VulnScanner
```

Then follow the interactive prompts to scan URLs or files.

## Project Structure

```
LEAKFINDER/
├── VulnScanner.java    # Core vulnerability scanner
├── ApiServer.java      # REST API server for web frontend
├── index.html          # Web frontend HTML
├── style.css           # Styling for web interface
├── script.js           # Frontend JavaScript
└── README.md           # This file
```

## API Endpoints

- `POST /api/scan/url` - Scan a website URL
  - Body: `{"url": "example.com"}`
  
- `POST /api/scan/file` - Scan a local file
  - Body: `{"filePath": "/path/to/file"}`

## Notes

- The scanner performs basic security checks and is intended for educational purposes
- For comprehensive security assessments, consider using professional tools like OWASP ZAP, Burp Suite, or Nmap
- Always ensure you have permission before scanning websites

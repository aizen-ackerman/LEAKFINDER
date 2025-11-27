import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;

// Check result class
class CheckResult {
    private String name;
    private boolean passed;
    private List<String> issues;
    private String severity;

    public CheckResult(String name, boolean passed, List<String> issues, String severity) {
        this.name = name;
        this.passed = passed;
        this.issues = issues;
        this.severity = severity;
    }

    public String getName() { return name; }
    public boolean isPassed() { return passed; }
    public List<String> getIssues() { return issues; }
    public String getSeverity() { return severity; }
}

class ScanResults {
    private String url;
    private String timestamp;
    private List<CheckResult> checks;
    private Map<String, Integer> summary;

    public ScanResults(String url, String timestamp, List<CheckResult> checks) {
        this.url = url;
        this.timestamp = timestamp;
        this.checks = checks;
        this.summary = calculateSummary();
    }

    private Map<String, Integer> calculateSummary() {
        Map<String, Integer> summary = new HashMap<>();
        int total = checks.size();
        int passed = 0;
        int failed = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        for (CheckResult check : checks) {
            if (check.isPassed()) {
                passed++;
            } else {
                failed++;
                switch (check.getSeverity()) {
                    case "high": high++; break;
                    case "medium": medium++; break;
                    case "low": low++; break;
                }
            }
        }

        summary.put("total", total);
        summary.put("passed", passed);
        summary.put("failed", failed);
        summary.put("high", high);
        summary.put("medium", medium);
        summary.put("low", low);

        return summary;
    }

    public String getUrl() { return url; }
    public String getTimestamp() { return timestamp; }
    public List<CheckResult> getChecks() { return checks; }
    public Map<String, Integer> getSummary() { return summary; }
}

public class VulnScanner {
    
    private CheckResult checkHardcodedCredentials(String content) {
        List<String> issues = new ArrayList<>();
        Map<String, String> patterns = new LinkedHashMap<>();
        patterns.put("password\\s*=\\s*[\"'][^\"']+[\"']", "Hardcoded password found");
        patterns.put("api[_-]?key\\s*=\\s*[\"'][^\"']+[\"']", "Hardcoded API key found");
        patterns.put("secret\\s*=\\s*[\"'][^\"']+[\"']", "Hardcoded secret found");
        patterns.put("token\\s*=\\s*[\"'][^\"']+[\"']", "Hardcoded token found");
        patterns.put("private[_-]?key\\s*=\\s*[\"'][^\"']+[\"']", "Private key found");

        for (Map.Entry<String, String> entry : patterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(content);
            int count = 0;
            while (matcher.find()) count++;
            
            if (count > 0) {
                String plural = count > 1 ? "s" : "";
                issues.add(entry.getValue() + " (" + count + " occurrence" + plural + ")");
            }
        }

        if (issues.isEmpty()) {
            issues.add("No hardcoded credentials detected");
        }

        return new CheckResult("Hardcoded Credentials", issues.size() == 1 && 
            issues.get(0).equals("No hardcoded credentials detected"), issues, "high");
    }

    private CheckResult checkSQLInjection(String content) {
        List<String> issues = new ArrayList<>();
        Map<String, String> patterns = new LinkedHashMap<>();
        patterns.put("SELECT\\s+.*\\s+FROM\\s+.*WHERE.*\\+", "Potential SQL injection via string concatenation");
        patterns.put("execute\\s*\\(\\s*[\"'].*\\+", "Dynamic SQL execution detected");
        patterns.put("query\\s*\\(\\s*[\"'].*\\+.*[\"']\\s*\\)", "Unsafe query construction");

        for (Map.Entry<String, String> entry : patterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(content).find()) {
                issues.add(entry.getValue());
            }
        }

        if (issues.isEmpty()) {
            issues.add("No SQL injection patterns detected");
        }

        return new CheckResult("SQL Injection Patterns", issues.size() == 1 && 
            issues.get(0).equals("No SQL injection patterns detected"), issues, "high");
    }

    private CheckResult checkXSSVulnerabilities(String content) {
        List<String> issues = new ArrayList<>();
        Map<String, String> patterns = new LinkedHashMap<>();
        patterns.put("innerHTML\\s*=\\s*[^\"']", "Unsafe innerHTML assignment");
        patterns.put("document\\.write\\s*\\(", "Use of document.write (XSS risk)");
        patterns.put("eval\\s*\\(", "Use of eval() function (XSS/Code injection risk)");
        patterns.put("dangerouslySetInnerHTML", "Use of dangerouslySetInnerHTML in React");
        patterns.put("v-html\\s*=", "Use of v-html in Vue (XSS risk)");

        for (Map.Entry<String, String> entry : patterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(content);
            int count = 0;
            while (matcher.find()) count++;
            
            if (count > 0) {
                String plural = count > 1 ? "s" : "";
                issues.add(entry.getValue() + " (" + count + " occurrence" + plural + ")");
            }
        }

        if (issues.isEmpty()) {
            issues.add("No XSS vulnerabilities detected");
        }

        return new CheckResult("XSS Vulnerabilities", issues.size() == 1 && 
            issues.get(0).equals("No XSS vulnerabilities detected"), issues, "high");
    }

    private CheckResult checkInsecureDependencies(String content) {
        List<String> issues = new ArrayList<>();

        // Check for CDN links with no integrity attribute
        Pattern cdnPattern = Pattern.compile("<script[^>]+src=[\"']?(https?://cdn[^\"']+)[\"']?[^>]*>", 
            Pattern.CASE_INSENSITIVE);
        Matcher matcher = cdnPattern.matcher(content);
        
        while (matcher.find()) {
            String scriptTag = matcher.group(0);
            if (!scriptTag.contains("integrity=")) {
                issues.add("CDN script without SRI integrity check: " + matcher.group(1));
            }
        }

        // Check for HTTP CDN links
        Pattern httpCdnPattern = Pattern.compile("<script[^>]+src=[\"']?(http://[^\"']+)[\"']?", 
            Pattern.CASE_INSENSITIVE);
        if (httpCdnPattern.matcher(content).find()) {
            issues.add("Insecure HTTP protocol used for script loading");
        }

        if (issues.isEmpty()) {
            issues.add("No insecure dependency issues detected");
        }

        return new CheckResult("Insecure Dependencies", issues.size() == 1 && 
            issues.get(0).equals("No insecure dependency issues detected"), issues, "medium");
    }

    private CheckResult checkSensitiveDataExposure(String content) {
        List<String> issues = new ArrayList<>();
        Map<String, String> patterns = new LinkedHashMap<>();
        patterns.put("console\\.log\\(", "Console.log statements (may leak sensitive data)");
        patterns.put("debugger;", "Debugger statements found");
        patterns.put("localhost|127\\.0\\.0\\.1", "Localhost references found");
        patterns.put("(test|debug|dev).*password", "Test/debug credentials found");
        patterns.put("api\\.example\\.com", "Example API endpoints found");

        for (Map.Entry<String, String> entry : patterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(content);
            int count = 0;
            while (matcher.find()) count++;
            
            if (count > 0) {
                String plural = count > 1 ? "s" : "";
                issues.add(entry.getValue() + " (" + count + " occurrence" + plural + ")");
            }
        }

        if (issues.isEmpty()) {
            issues.add("No sensitive data exposure detected");
        }

        return new CheckResult("Sensitive Data Exposure", issues.size() == 1 && 
            issues.get(0).equals("No sensitive data exposure detected"), issues, "medium");
    }

    private CheckResult checkInsecureCryptography(String content) {
        List<String> issues = new ArrayList<>();
        Map<String, String> patterns = new LinkedHashMap<>();
        patterns.put("md5\\s*\\(", "MD5 hashing (cryptographically broken)");
        patterns.put("sha1\\s*\\(", "SHA1 hashing (weak)");
        patterns.put("Math\\.random\\(\\)", "Math.random() used (not cryptographically secure)");
        patterns.put("btoa\\(", "Base64 encoding (not encryption)");

        for (Map.Entry<String, String> entry : patterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(content).find()) {
                issues.add(entry.getValue());
            }
        }

        if (issues.isEmpty()) {
            issues.add("No insecure cryptography detected");
        }

        return new CheckResult("Insecure Cryptography", issues.size() == 1 && 
            issues.get(0).equals("No insecure cryptography detected"), issues, "medium");
    }

    private CheckResult checkOutdatedLibraries(String content) {
        List<String> issues = new ArrayList<>();
        Map<String, String> outdated = new LinkedHashMap<>();
        outdated.put("jquery@1\\.", "jQuery 1.x (outdated, security vulnerabilities)");
        outdated.put("angular@1\\.", "AngularJS 1.x (end of life)");
        outdated.put("react@15\\.", "React 15.x (outdated)");
        outdated.put("bootstrap@3\\.", "Bootstrap 3.x (outdated)");

        for (Map.Entry<String, String> entry : outdated.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(content).find()) {
                issues.add(entry.getValue());
            }
        }

        if (issues.isEmpty()) {
            issues.add("No outdated libraries detected in code");
        }

        return new CheckResult("Outdated Libraries", issues.size() == 1 && 
            issues.get(0).equals("No outdated libraries detected in code"), issues, "low");
    }

    private CheckResult checkCORSMisconfigurations(String content) {
        List<String> issues = new ArrayList<>();

        Pattern wildcardPattern = Pattern.compile("Access-Control-Allow-Origin:\\s*\\*", 
            Pattern.CASE_INSENSITIVE);
        if (wildcardPattern.matcher(content).find()) {
            issues.add("Wildcard CORS policy detected (Access-Control-Allow-Origin: *)");
        }

        Pattern credentialsPattern = Pattern.compile("Access-Control-Allow-Credentials:\\s*true", 
            Pattern.CASE_INSENSITIVE);
        if (credentialsPattern.matcher(content).find() && wildcardPattern.matcher(content).find()) {
            issues.add("Dangerous CORS config: credentials with wildcard origin");
        }

        if (issues.isEmpty()) {
            issues.add("No CORS misconfigurations detected");
        }

        return new CheckResult("CORS Misconfigurations", issues.size() == 1 && 
            issues.get(0).equals("No CORS misconfigurations detected"), issues, "high");
    }

    // URL Vulnerability Checks
    private CheckResult checkSSLTLS(String targetUrl) {
        List<String> issues = new ArrayList<>();
        if (!targetUrl.startsWith("https://")) {
            issues.add("Site does not use HTTPS encryption");
        } else {
            issues.add("HTTPS encryption enabled");
        }

        return new CheckResult("SSL/TLS Security", targetUrl.startsWith("https://"), issues, "high");
    }

    private CheckResult checkSecurityHeaders(String targetUrl) {
        List<String> issues = new ArrayList<>();
        try {
            URI uri = new URI(targetUrl);
            URL url = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.connect();

            Map<String, List<String>> headers = conn.getHeaderFields();

            if (!hasHeader(headers, "strict-transport-security")) {
                issues.add("Missing Strict-Transport-Security header");
            }
            if (!hasHeader(headers, "x-frame-options")) {
                issues.add("Missing X-Frame-Options header (Clickjacking protection)");
            }
            if (!hasHeader(headers, "x-content-type-options")) {
                issues.add("Missing X-Content-Type-Options header");
            }
            if (!hasHeader(headers, "content-security-policy")) {
                issues.add("Missing Content-Security-Policy header");
            }
            if (!hasHeader(headers, "x-xss-protection")) {
                issues.add("Missing X-XSS-Protection header");
            }

            if (issues.isEmpty()) {
                issues.add("All security headers present");
            }

            conn.disconnect();
            return new CheckResult("Security Headers", issues.size() == 1 && 
                issues.get(0).equals("All security headers present"), issues, "medium");

        } catch (Exception e) {
            issues.add("Unable to check security headers - " + e.getMessage());
            return new CheckResult("Security Headers", false, issues, "low");
        }
    }

    private CheckResult checkCookieSecurity(String targetUrl) {
        List<String> issues = new ArrayList<>();
        try {
            URI uri = new URI(targetUrl);
            URL url = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.connect();

            Map<String, List<String>> headers = conn.getHeaderFields();
            List<String> cookies = headers.get("Set-Cookie");

            if (cookies != null && !cookies.isEmpty()) {
                String cookieStr = String.join("; ", cookies);
                
                if (!cookieStr.contains("Secure")) {
                    issues.add("Cookies not marked as Secure");
                }
                if (!cookieStr.contains("HttpOnly")) {
                    issues.add("Cookies not marked as HttpOnly");
                }
                if (!cookieStr.contains("SameSite")) {
                    issues.add("Cookies missing SameSite attribute");
                }
            }

            if (issues.isEmpty()) {
                issues.add("Cookie security attributes properly configured");
            }

            conn.disconnect();
            return new CheckResult("Cookie Security", issues.size() == 1 && 
                issues.get(0).equals("Cookie security attributes properly configured"), issues, "medium");

        } catch (Exception e) {
            issues.add("Unable to check cookies - " + e.getMessage());
            return new CheckResult("Cookie Security", false, issues, "low");
        }
    }

    private CheckResult checkMixedContent(String targetUrl) {
        List<String> issues = new ArrayList<>();
        if (targetUrl.startsWith("https://")) {
            try {
                URI uri = new URI(targetUrl);
                URL url = uri.toURL();
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(10000);
                
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder html = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    html.append(line);
                }
                in.close();

                Pattern httpPattern = Pattern.compile("http://[^\"'\\s]+");
                Matcher matcher = httpPattern.matcher(html.toString());
                int count = 0;
                while (matcher.find()) count++;

                if (count > 0) {
                    issues.add("Found " + count + " insecure HTTP resources on HTTPS page");
                } else {
                    issues.add("No mixed content detected");
                }

                conn.disconnect();
                return new CheckResult("Mixed Content", count == 0, issues, "medium");

            } catch (Exception e) {
                issues.add("Unable to check for mixed content - " + e.getMessage());
                return new CheckResult("Mixed Content", false, issues, "low");
            }
        }
        issues.add("Site not using HTTPS");
        return new CheckResult("Mixed Content", false, issues, "high");
    }

    private CheckResult checkInformationDisclosure(String targetUrl) {
        List<String> issues = new ArrayList<>();
        try {
            URI uri = new URI(targetUrl);
            URL url = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.connect();

            String serverHeader = conn.getHeaderField("Server");
            String poweredBy = conn.getHeaderField("X-Powered-By");

            if (serverHeader != null) {
                issues.add("Server header exposes: " + serverHeader);
            }
            if (poweredBy != null) {
                issues.add("X-Powered-By header exposes: " + poweredBy);
            }

            if (issues.isEmpty()) {
                issues.add("No obvious information disclosure");
            }

            conn.disconnect();
            return new CheckResult("Information Disclosure", issues.size() == 1 && 
                issues.get(0).equals("No obvious information disclosure"), issues, "low");

        } catch (Exception e) {
            issues.add("Unable to check headers - " + e.getMessage());
            return new CheckResult("Information Disclosure", false, issues, "low");
        }
    }

    private CheckResult checkCommonPatterns(String targetUrl) {
        List<String> issues = new ArrayList<>();
        try {
            URI uri = new URI(targetUrl);
            URL url = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder html = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                html.append(line);
            }
            in.close();

            String htmlContent = html.toString();

            // Check for potential XSS vulnerabilities
            if (htmlContent.contains("eval(") || htmlContent.contains("innerHTML")) {
                issues.add("Potentially dangerous JavaScript patterns detected");
            }

            // Check for exposed sensitive paths
            String[] sensitivePaths = {"/admin", "/.git", "/.env", "/config"};
            for (String path : sensitivePaths) {
                if (htmlContent.contains(path)) {
                    issues.add("Potential exposure of sensitive path: " + path);
                }
            }

            if (issues.isEmpty()) {
                issues.add("No common vulnerability patterns detected");
            }

            conn.disconnect();
            return new CheckResult("Common Vulnerability Patterns", issues.size() == 1 && 
                issues.get(0).equals("No common vulnerability patterns detected"), issues, "medium");

        } catch (Exception e) {
            issues.add("Unable to analyze content - " + e.getMessage());
            return new CheckResult("Common Vulnerability Patterns", false, issues, "low");
        }
    }

    private boolean hasHeader(Map<String, List<String>> headers, String headerName) {
        for (String key : headers.keySet()) {
            if (key != null && key.equalsIgnoreCase(headerName)) {
                return true;
            }
        }
        return false;
    }

    // Scan file for vulnerabilities
    public ScanResults scanFile(String filePath) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            
            System.out.println("\n" + "=".repeat(70));
            System.out.println("FILE VULNERABILITY SCAN");
            System.out.println("=".repeat(70));
            System.out.println("File: " + filePath);
            System.out.println("Scan started: " + LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            System.out.println("=".repeat(70) + "\n");

            List<CheckResult> scanResults = new ArrayList<>();
            
            CheckResult[] checks = {
                checkHardcodedCredentials(content),
                checkSQLInjection(content),
                checkXSSVulnerabilities(content),
                checkInsecureDependencies(content),
                checkSensitiveDataExposure(content),
                checkInsecureCryptography(content),
                checkOutdatedLibraries(content),
                checkCORSMisconfigurations(content)
            };

            int total = checks.length;
            for (int i = 0; i < total; i++) {
                System.out.print("[" + (i + 1) + "/" + total + "] Checking " + 
                    checks[i].getName() + "... ");
                scanResults.add(checks[i]);
                System.out.println(checks[i].isPassed() ? "✓" : "✗");
                Thread.sleep(300);
            }

            ScanResults results = new ScanResults(filePath, 
                LocalDateTime.now().toString(), scanResults);
            displayResults(results);
            return results;

        } catch (Exception e) {
            System.out.println("Error reading file: " + e.getMessage());
            return null;
        }
    }

    // Scan website for vulnerabilities
    public ScanResults scanWebsite(String urlString) {
        String targetUrl = urlString;
        if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
            targetUrl = "https://" + urlString;
        }

        System.out.println("\n" + "=".repeat(70));
        System.out.println("WEB VULNERABILITY SCAN");
        System.out.println("=".repeat(70));
        System.out.println("URL: " + targetUrl);
        System.out.println("Scan started: " + LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        System.out.println("=".repeat(70) + "\n");

        List<CheckResult> scanResults = new ArrayList<>();
        
        CheckResult[] checks = {
            checkSSLTLS(targetUrl),
            checkSecurityHeaders(targetUrl),
            checkCookieSecurity(targetUrl),
            checkMixedContent(targetUrl),
            checkInformationDisclosure(targetUrl),
            checkCommonPatterns(targetUrl)
        };

        int total = checks.length;
        for (int i = 0; i < total; i++) {
            System.out.print("[" + (i + 1) + "/" + total + "] Checking " + 
                checks[i].getName() + "... ");
            scanResults.add(checks[i]);
            System.out.println(checks[i].isPassed() ? "✓" : "✗");
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        ScanResults results = new ScanResults(targetUrl, 
            LocalDateTime.now().toString(), scanResults);
        displayResults(results);
        return results;
    }

    // Display scan results
    private void displayResults(ScanResults results) {
        Map<String, Integer> summary = results.getSummary();

        System.out.println("\n" + "=".repeat(70));
        System.out.println("SCAN SUMMARY");
        System.out.println("=".repeat(70));
        System.out.println("Total Checks: " + summary.get("total"));
        System.out.println("Passed: " + summary.get("passed"));
        System.out.println("Failed: " + summary.get("failed"));
        System.out.println("  - High Severity: " + summary.get("high"));
        System.out.println("  - Medium Severity: " + summary.get("medium"));
        System.out.println("  - Low Severity: " + summary.get("low"));
        System.out.println("=".repeat(70) + "\n");

        System.out.println("DETAILED RESULTS");
        System.out.println("=".repeat(70) + "\n");

        for (CheckResult check : results.getChecks()) {
            String status = check.isPassed() ? "✓ PASSED" : "✗ FAILED";
            String severity = check.getSeverity().toUpperCase();

            System.out.println("[" + status + "] " + check.getName());
            System.out.println("Severity: " + severity);
            System.out.println("Issues:");
            for (String issue : check.getIssues()) {
                System.out.println("  • " + issue);
            }
            System.out.println("-".repeat(70) + "\n");
        }

        System.out.println("Note: This scanner performs basic security checks.");
        System.out.println("For comprehensive security assessments, consider using professional tools");
        System.out.println("like OWASP ZAP, Burp Suite, or Nmap.\n");
    }

    // Save report to file
    public void saveReport(ScanResults results, String outputFile) {
        if (outputFile == null) {
            outputFile = "vulnerability-scan-" + System.currentTimeMillis() + ".txt";
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("Web Vulnerability Scan Report");
            writer.println("-".repeat(50));
            writer.println("URL: " + results.getUrl());
            writer.println("Scan Date: " + LocalDateTime.parse(results.getTimestamp()).format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            writer.println();
            writer.println("SUMMARY");
            writer.println("-".repeat(50));
            
            Map<String, Integer> summary = results.getSummary();
            writer.println("Total Checks: " + summary.get("total"));
            writer.println("Passed: " + summary.get("passed"));
            writer.println("Failed: " + summary.get("failed"));
            writer.println("  - High Severity: " + summary.get("high"));
            writer.println("  - Medium Severity: " + summary.get("medium"));
            writer.println("  - Low Severity: " + summary.get("low"));
            writer.println();
            writer.println("DETAILED RESULTS");
            writer.println("-".repeat(50));

            for (CheckResult check : results.getChecks()) {
                writer.println();
                writer.println(check.getName());
                writer.println("Status: " + (check.isPassed() ? "PASSED" : "FAILED"));
                writer.println("Severity: " + check.getSeverity().toUpperCase());
                writer.println("Issues:");
                for (String issue : check.getIssues()) {
                    writer.println("  - " + issue);
                }
            }

            System.out.println("\n✓ Report saved to: " + outputFile);
        } catch (IOException e) {
            System.out.println("\n✗ Error saving report: " + e.getMessage());
        }
    }

    // Main method
    public static void main(String[] args) {
        VulnScanner scanner = new VulnScanner();
        Scanner input = new Scanner(System.in);

        System.out.println("=".repeat(70));
        System.out.println(" ".repeat(15) + "WEB VULNERABILITY SCANNER");
        System.out.println(" ".repeat(10) + "Identify security vulnerabilities in websites");
        System.out.println("=".repeat(70));

        while (true) {
            System.out.println("\nSCAN OPTIONS:");
            System.out.println("1. Scan URL");
            System.out.println("2. Scan File");
            System.out.println("3. Exit");

            System.out.print("\nEnter your choice (1-3): ");
            String choice = input.nextLine().trim();

            if (choice.equals("1")) {
                System.out.print("\nEnter website URL (e.g., example.com): ");
                String url = input.nextLine().trim();
                if (!url.isEmpty()) {
                    ScanResults results = scanner.scanWebsite(url);
                    if (results != null) {
                        System.out.print("\nSave report? (y/n): ");
                        String save = input.nextLine().trim().toLowerCase();
                        if (save.equals("y")) {
                            scanner.saveReport(results, null);
                        }
                    }
                } else {
                    System.out.println("Invalid URL!");
                }

            } else if (choice.equals("2")) {
                System.out.print("\nEnter file path: ");
                String filePath = input.nextLine().trim();
                if (!filePath.isEmpty()) {
                    ScanResults results = scanner.scanFile(filePath);
                    if (results != null) {
                        System.out.print("\nSave report? (y/n): ");
                        String save = input.nextLine().trim().toLowerCase();
                        if (save.equals("y")) {
                            scanner.saveReport(results, null);
                        }
                    }
                } else {
                    System.out.println("Invalid file path!");
                }

            } else if (choice.equals("3")) {
                System.out.println("\nThank you for using Web Vulnerability Scanner!");
                break;

            } else {
                System.out.println("Invalid choice! Please try again.");
            }
        }

        input.close();
    }
}
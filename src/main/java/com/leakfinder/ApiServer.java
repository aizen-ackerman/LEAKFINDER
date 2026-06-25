package com.leakfinder;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class ApiServer {
    private VulnScanner scanner;
    private HttpServer server;
    private static final int PORT = 8080;

    // Scan History
    static class ScanHistoryItem {
        int id;
        String type;
        String target;
        String timestamp;
        ScanResults results;

        public ScanHistoryItem(int id, String type, String target, String timestamp, ScanResults results) {
            this.id = id;
            this.type = type;
            this.target = target;
            this.timestamp = timestamp;
            this.results = results;
        }
    }

    private final List<ScanHistoryItem> scanHistory = new ArrayList<>();
    private int nextScanId = 1;

    // XposedOrNot Cache
    private String cachedBreaches = null;
    private long cacheTimestamp = 0;
    private static final long CACHE_TTL_MS = 3600000; // 1 hour

    public ApiServer() {
        this.scanner = new VulnScanner();
        preseedHistory();
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        server.createContext("/api/scan/url", this::handleScanUrl);
        server.createContext("/api/scan/file", this::handleScanFile);
        server.createContext("/api/upload/scan", this::handleFileUpload);
        server.createContext("/api/scans/history", this::handleScanHistory);
        server.createContext("/api/breaches", this::handleBreaches);
        server.createContext("/", this::handleStatic);
        
        server.setExecutor(null);
        server.start();
        System.out.println("API Server started on http://localhost:" + PORT);
        System.out.println("Open http://localhost:" + PORT + " in your browser");
    }

    private void handleScanUrl(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("OPTIONS")) {
            handleCORS(exchange);
            return;
        }
        
        if (!exchange.getRequestMethod().equals("POST")) {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            String requestBody = reader.lines().collect(Collectors.joining("\n"));

            String url = extractJsonValue(requestBody, "url");

            if (url == null || url.isEmpty()) {
                sendResponse(exchange, 400, "{\"error\":\"URL is required\"}");
                return;
            }

            // Suppress console output during scan
            PrintStream originalOut = System.out;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream nullStream = new PrintStream(baos);
            System.setOut(nullStream);
            
            try {
                ScanResults results = scanner.scanWebsite(url);
                System.setOut(originalOut);
                
                if (results == null) {
                    sendResponse(exchange, 500, "{\"error\":\"Scan failed - no results returned\"}");
                    return;
                }

                synchronized (scanHistory) {
                    scanHistory.add(new ScanHistoryItem(nextScanId++, "URL", url, results.getTimestamp(), results));
                }

                String jsonResponse = convertToJson(results);
                sendResponse(exchange, 200, jsonResponse);
            } catch (Exception scanException) {
                System.setOut(originalOut);
                scanException.printStackTrace(); // Log error for debugging
                String errorMsg = scanException.getMessage();
                if (errorMsg == null || errorMsg.isEmpty()) {
                    errorMsg = scanException.getClass().getSimpleName() + " occurred during scan";
                }
                // Include more details in error
                if (scanException.getCause() != null) {
                    errorMsg += ": " + scanException.getCause().getMessage();
                }
                sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + "\"}");
            }

        } catch (Exception e) {
            String errorMsg = e.getMessage();
            if (errorMsg == null || errorMsg.isEmpty()) {
                errorMsg = "Unknown error occurred";
            }
            sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + "\"}");
        }
    }

    private void handleScanFile(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("OPTIONS")) {
            handleCORS(exchange);
            return;
        }
        
        if (!exchange.getRequestMethod().equals("POST")) {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            String requestBody = reader.lines().collect(Collectors.joining("\n"));

            String filePath = extractJsonValue(requestBody, "filePath");

            if (filePath == null || filePath.isEmpty()) {
                sendResponse(exchange, 400, "{\"error\":\"File path is required\"}");
                return;
            }

            // Suppress console output during scan
            PrintStream originalOut = System.out;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream nullStream = new PrintStream(baos);
            System.setOut(nullStream);
            
            try {
                ScanResults results = scanner.scanFile(filePath);
                System.setOut(originalOut);
                
                if (results == null) {
                    sendResponse(exchange, 500, "{\"error\":\"Scan failed - no results returned\"}");
                    return;
                }

                synchronized (scanHistory) {
                    scanHistory.add(new ScanHistoryItem(nextScanId++, "FILE", filePath, results.getTimestamp(), results));
                }

                String jsonResponse = convertToJson(results);
                sendResponse(exchange, 200, jsonResponse);
            } catch (Exception scanException) {
                System.setOut(originalOut);
                scanException.printStackTrace(); // Log error for debugging
                String errorMsg = scanException.getMessage();
                if (errorMsg == null || errorMsg.isEmpty()) {
                    errorMsg = scanException.getClass().getSimpleName() + " occurred during scan";
                }
                // Include more details in error
                if (scanException.getCause() != null) {
                    errorMsg += ": " + scanException.getCause().getMessage();
                }
                sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + "\"}");
            }

        } catch (Exception e) {
            String errorMsg = e.getMessage();
            if (errorMsg == null || errorMsg.isEmpty()) {
                errorMsg = "Unknown error occurred";
            }
            sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + "\"}");
        }
    }

    private void handleFileUpload(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("OPTIONS")) {
            handleCORS(exchange);
            return;
        }
        
        if (!exchange.getRequestMethod().equals("POST")) {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        File tempFile = null;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            
            StringBuilder requestBodyBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                requestBodyBuilder.append(line);
            }
            String requestBody = requestBodyBuilder.toString();
            
            // Parse JSON
            String fileName = extractJsonValue(requestBody, "fileName");
            String fileContent = extractJsonValue(requestBody, "fileContent");
            String isBase64Str = extractJsonValue(requestBody, "isBase64");
            boolean isBase64 = "true".equals(isBase64Str);
            
            if (fileContent == null || fileContent.isEmpty()) {
                sendResponse(exchange, 400, "{\"error\":\"File content is required\"}");
                return;
            }

            // Decode base64 if needed
            String decodedContent;
            if (isBase64) {
                try {
                    byte[] decodedBytes = java.util.Base64.getDecoder().decode(fileContent);
                    decodedContent = new String(decodedBytes, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    sendResponse(exchange, 400, "{\"error\":\"Invalid base64 encoding: " + escapeJson(e.getMessage()) + "\"}");
                    return;
                }
            } else {
                decodedContent = fileContent;
            }

            // Create temporary file
            String extension = "";
            if (fileName != null && fileName.contains(".")) {
                extension = fileName.substring(fileName.lastIndexOf("."));
            }
            tempFile = File.createTempFile("scan_", extension);
            tempFile.deleteOnExit();

            // Write file content to temp file using Files.write for reliability
            String tempFilePath = tempFile.getAbsolutePath();
            try {
                Files.write(Paths.get(tempFilePath), decodedContent.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                sendResponse(exchange, 500, "{\"error\":\"Failed to write temporary file: " + escapeJson(e.getMessage()) + "\"}");
                return;
            }
            
            // Verify file was written
            if (!tempFile.exists()) {
                sendResponse(exchange, 500, "{\"error\":\"Failed to create temporary file\"}");
                return;
            }
            
            if (tempFile.length() == 0 && decodedContent.length() > 0) {
                sendResponse(exchange, 500, "{\"error\":\"Temporary file is empty but content was provided\"}");
                return;
            }
            
            System.out.println("DEBUG: Created temp file: " + tempFilePath + " (size: " + tempFile.length() + " bytes, content length: " + decodedContent.length() + ")");

            // Verify file exists and is readable before scanning
            if (!tempFile.exists()) {
                sendResponse(exchange, 500, "{\"error\":\"Temporary file does not exist: " + escapeJson(tempFilePath) + "\"}");
                return;
            }
            
            if (!tempFile.canRead()) {
                sendResponse(exchange, 500, "{\"error\":\"Temporary file is not readable: " + escapeJson(tempFilePath) + "\"}");
                return;
            }
            
            // Suppress console output during scan but capture errors
            PrintStream originalOut = System.out;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream nullStream = new PrintStream(baos);
            System.setOut(nullStream);
            
            try {
                ScanResults results = scanner.scanFile(tempFilePath);
                System.setOut(originalOut);
                
                if (results == null) {
                    // Check if there's any error output captured
                    String errorOutput = baos.toString();
                    String errorMsg = "Scan failed - file may not exist or could not be read";
                    if (errorOutput.contains("Error") || errorOutput.contains("not found")) {
                        errorMsg += ". Details: " + errorOutput.substring(Math.max(0, errorOutput.length() - 200));
                    }
                    sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + ". File path: " + escapeJson(tempFilePath) + "\"}");
                    return;
                }

                synchronized (scanHistory) {
                    scanHistory.add(new ScanHistoryItem(nextScanId++, "FILE", fileName != null ? fileName : "uploaded_file", results.getTimestamp(), results));
                }

                String jsonResponse = convertToJson(results);
                sendResponse(exchange, 200, jsonResponse);
            } catch (java.nio.file.NoSuchFileException e) {
                System.setOut(originalOut);
                sendResponse(exchange, 500, "{\"error\":\"File not found: " + escapeJson(tempFilePath) + ". " + escapeJson(e.getMessage()) + "\"}");
            } catch (java.io.FileNotFoundException e) {
                System.setOut(originalOut);
                sendResponse(exchange, 500, "{\"error\":\"File not found: " + escapeJson(tempFilePath) + ". " + escapeJson(e.getMessage()) + "\"}");
            } catch (Exception scanException) {
                System.setOut(originalOut);
                scanException.printStackTrace();
                String errorMsg = scanException.getMessage();
                if (errorMsg == null || errorMsg.isEmpty()) {
                    errorMsg = scanException.getClass().getSimpleName() + " occurred during scan";
                }
                if (scanException.getCause() != null) {
                    errorMsg += ": " + scanException.getCause().getMessage();
                }
                // Include captured output if any
                String capturedOutput = baos.toString();
                if (!capturedOutput.isEmpty()) {
                    errorMsg += ". Output: " + capturedOutput.substring(Math.max(0, capturedOutput.length() - 200));
                }
                sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + ". File: " + escapeJson(tempFilePath) + "\"}");
            }

        } catch (Exception e) {
            String errorMsg = e.getMessage();
            if (errorMsg == null || errorMsg.isEmpty()) {
                errorMsg = "Unknown error occurred";
            }
            sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(errorMsg) + "\"}");
        } finally {
            // Clean up temp file
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }

    private void handleStatic(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if (path.equals("/")) {
            path = "/index.html";
        }
        
        if (path.contains("..")) {
            sendResponse(exchange, 400, "{\"error\":\"Bad request\"}");
            return;
        }

        String filename = path.startsWith("/") ? path.substring(1) : path;
        File file = new File(filename);
        
        if (!file.exists() || file.isDirectory()) {
            file = new File("src/main/resources/static/" + filename);
            if (!file.exists() || file.isDirectory()) {
                sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
                return;
            }
        }

        String contentType = "application/octet-stream";
        if (filename.endsWith(".html")) contentType = "text/html";
        else if (filename.endsWith(".css")) contentType = "text/css";
        else if (filename.endsWith(".js")) contentType = "application/javascript";
        else if (filename.endsWith(".svg")) contentType = "image/svg+xml";
        else if (filename.endsWith(".png")) contentType = "image/png";

        serveFile(exchange, file.getPath(), contentType);
    }

    private void serveFile(HttpExchange exchange, String filename, String contentType) throws IOException {
        try {
            File file = new File(filename);
            if (!file.exists()) {
                sendResponse(exchange, 404, "{\"error\":\"File not found\"}");
                return;
            }

            byte[] fileBytes = java.nio.file.Files.readAllBytes(file.toPath());
            
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, fileBytes.length);
            
            OutputStream os = exchange.getResponseBody();
            os.write(fileBytes);
            os.close();
        } catch (Exception e) {
            sendResponse(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
        }
    }

    private String extractJsonValue(String json, String key) {
        // For string values: match "key": "value" where value may be large (base64)
        // Use a pattern that handles escaped quotes inside the value
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"",
            java.util.regex.Pattern.DOTALL
        );
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1);
        }
        // For boolean/number values: match "key": value (no quotes)
        java.util.regex.Pattern pb = java.util.regex.Pattern.compile(
            "\"" + key + "\"\\s*:\\s*(true|false|[0-9]+)"
        );
        java.util.regex.Matcher mb = pb.matcher(json);
        if (mb.find()) {
            return mb.group(1);
        }
        return null;
    }


    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    private String convertToJson(ScanResults results) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"url\":\"").append(escapeJson(results.getUrl())).append("\",");
        json.append("\"timestamp\":\"").append(escapeJson(results.getTimestamp())).append("\",");
        
        Map<String, Integer> summaryMap = results.getSummary();
        json.append("\"summary\":{");
        json.append("\"total\":").append(summaryMap.get("total")).append(",");
        json.append("\"passed\":").append(summaryMap.get("passed")).append(",");
        json.append("\"failed\":").append(summaryMap.get("failed")).append(",");
        json.append("\"high\":").append(summaryMap.get("high")).append(",");
        json.append("\"medium\":").append(summaryMap.get("medium")).append(",");
        json.append("\"low\":").append(summaryMap.get("low"));
        json.append("},");
        
        json.append("\"checks\":[");
        boolean first = true;
        for (CheckResult check : results.getChecks()) {
            if (!first) json.append(",");
            first = false;
            
            json.append("{");
            json.append("\"name\":\"").append(escapeJson(check.getName())).append("\",");
            json.append("\"passed\":").append(check.isPassed()).append(",");
            json.append("\"severity\":\"").append(escapeJson(check.getSeverity())).append("\",");
            json.append("\"issues\":[");
            
            boolean firstIssue = true;
            for (String issue : check.getIssues()) {
                if (!firstIssue) json.append(",");
                firstIssue = false;
                json.append("\"").append(escapeJson(issue)).append("\"");
            }
            json.append("]");
            json.append("}");
        }
        json.append("]");
        json.append("}");
        
        return json.toString();
    }

    private void handleCORS(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        exchange.sendResponseHeaders(200, 0);
        exchange.close();
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(responseBytes);
        os.close();
    }

    // Preseed history with project codebase scans
    private void preseedHistory() {
        try {
            System.out.println("Pre-seeding scan history with project files...");
            File pomFile = new File("pom.xml");
            if (pomFile.exists()) {
                ScanResults r1 = scanner.scanFile("pom.xml");
                if (r1 != null) {
                    scanHistory.add(new ScanHistoryItem(nextScanId++, "FILE", "pom.xml", r1.getTimestamp(), r1));
                }
            }
            File runFile = new File("run.sh");
            if (runFile.exists()) {
                ScanResults r2 = scanner.scanFile("run.sh");
                if (r2 != null) {
                    scanHistory.add(new ScanHistoryItem(nextScanId++, "FILE", "run.sh", r2.getTimestamp(), r2));
                }
            }
            File apiFile = new File("src/main/java/com/leakfinder/ApiServer.java");
            if (apiFile.exists()) {
                ScanResults r3 = scanner.scanFile("src/main/java/com/leakfinder/ApiServer.java");
                if (r3 != null) {
                    scanHistory.add(new ScanHistoryItem(nextScanId++, "FILE", "src/main/java/com/leakfinder/ApiServer.java", r3.getTimestamp(), r3));
                }
            }
            System.out.println("Scan history pre-seeded successfully. Scans loaded: " + scanHistory.size());
        } catch (Exception e) {
            System.err.println("Failed to preseed history: " + e.getMessage());
        }
    }

    private void handleScanHistory(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("OPTIONS")) {
            handleCORS(exchange);
            return;
        }
        
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        
        if (method.equals("GET")) {
            if (path.startsWith("/api/scans/history/")) {
                String idStr = path.substring("/api/scans/history/".length());
                try {
                    int id = Integer.parseInt(idStr);
                    ScanHistoryItem found = null;
                    synchronized (scanHistory) {
                        for (ScanHistoryItem item : scanHistory) {
                            if (item.id == id) {
                                found = item;
                                break;
                            }
                        }
                    }
                    if (found != null) {
                        sendResponse(exchange, 200, convertHistoryItemToJson(found));
                    } else {
                        sendResponse(exchange, 404, "{\"error\":\"Scan log not found\"}");
                    }
                } catch (NumberFormatException e) {
                    sendResponse(exchange, 400, "{\"error\":\"Invalid scan log ID\"}");
                }
            } else if (path.equals("/api/scans/history") || path.equals("/api/scans/history/")) {
                String json;
                synchronized (scanHistory) {
                    json = convertHistoryListToJson(scanHistory);
                }
                sendResponse(exchange, 200, json);
            } else {
                sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
            }
        } else {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
        }
    }

    private void handleBreaches(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("OPTIONS")) {
            handleCORS(exchange);
            return;
        }
        
        if (!exchange.getRequestMethod().equals("GET")) {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }
        
        long now = System.currentTimeMillis();
        String responseBody = null;
        
        synchronized (this) {
            if (cachedBreaches != null && (now - cacheTimestamp < CACHE_TTL_MS)) {
                responseBody = cachedBreaches;
            }
        }
        
        if (responseBody == null) {
            System.out.println("Fetching live breach directory from XposedOrNot...");
            responseBody = fetchUrl("https://api.xposedornot.com/v1/breaches");
            
            if (responseBody != null && responseBody.contains("\"exposedBreaches\"")) {
                synchronized (this) {
                    cachedBreaches = responseBody;
                    cacheTimestamp = now;
                }
            } else {
                System.out.println("Failed to fetch live breaches, using static fallback.");
                synchronized (this) {
                    if (cachedBreaches != null) {
                        responseBody = cachedBreaches;
                    } else {
                        responseBody = getFallbackBreachesJson();
                    }
                }
            }
        }
        
        sendResponse(exchange, 200, responseBody);
    }

    private String fetchUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            int status = conn.getResponseCode();
            if (status != 200) {
                return null;
            }
            
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    content.append(line);
                }
                return content.toString();
            }
        } catch (Exception e) {
            System.err.println("Failed to fetch from URL: " + urlString + " due to " + e.getMessage());
            return null;
        }
    }

    private String getFallbackBreachesJson() {
        return "{"
            + "\"status\":\"success\","
            + "\"message\":null,"
            + "\"exposedBreaches\":["
            + "{\"breachID\":\"CanvaDatabase\",\"domain\":\"canva.com\",\"exposedRecords\":137000000,\"breachedDate\":\"2019-05-01T00:00:00+00:00\",\"exposedData\":[\"Email addresses\",\"Passwords\",\"Names\"]},"
            + "{\"breachID\":\"LinkedInScrape\",\"domain\":\"linkedin.com\",\"exposedRecords\":700000000,\"breachedDate\":\"2021-06-01T00:00:00+00:00\",\"exposedData\":[\"Email addresses\",\"Phone numbers\",\"Job titles\"]},"
            + "{\"breachID\":\"AdobeExposure\",\"domain\":\"adobe.com\",\"exposedRecords\":152000000,\"breachedDate\":\"2013-10-01T00:00:00+00:00\",\"exposedData\":[\"Email addresses\",\"Password hints\"]},"
            + "{\"breachID\":\"DropboxLeak\",\"domain\":\"dropbox.com\",\"exposedRecords\":68000000,\"breachedDate\":\"2012-08-01T00:00:00+00:00\",\"exposedData\":[\"Email addresses\",\"Passwords\"]},"
            + "{\"breachID\":\"LedgerDatabase\",\"domain\":\"ledger.com\",\"exposedRecords\":1000000,\"breachedDate\":\"2020-12-01T00:00:00+00:00\",\"exposedData\":[\"Email addresses\",\"Physical addresses\",\"Phone numbers\"]}"
            + "]"
            + "}";
    }

    private String convertHistoryListToJson(List<ScanHistoryItem> list) {
        StringBuilder json = new StringBuilder();
        json.append("[");
        boolean first = true;
        for (ScanHistoryItem item : list) {
            if (!first) json.append(",");
            first = false;
            json.append(convertHistoryItemToJson(item));
        }
        json.append("]");
        return json.toString();
    }

    private String convertHistoryItemToJson(ScanHistoryItem item) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"id\":").append(item.id).append(",");
        json.append("\"target\":\"").append(escapeJson(item.target)).append("\",");
        json.append("\"targetType\":\"").append(escapeJson(item.type)).append("\",");
        json.append("\"severity\":\"").append(escapeJson(item.results.getSeverity())).append("\",");
        json.append("\"timestamp\":\"").append(escapeJson(item.timestamp)).append("\",");
        
        Map<String, Integer> summaryMap = item.results.getSummary();
        json.append("\"total\":").append(summaryMap.get("total")).append(",");
        json.append("\"passed\":").append(summaryMap.get("passed")).append(",");
        json.append("\"failed\":").append(summaryMap.get("failed")).append(",");
        json.append("\"high\":").append(summaryMap.get("high")).append(",");
        json.append("\"medium\":").append(summaryMap.get("medium")).append(",");
        json.append("\"low\":").append(summaryMap.get("low")).append(",");
        
        json.append("\"summary\":{");
        json.append("\"total\":").append(summaryMap.get("total")).append(",");
        json.append("\"passed\":").append(summaryMap.get("passed")).append(",");
        json.append("\"failed\":").append(summaryMap.get("failed")).append(",");
        json.append("\"high\":").append(summaryMap.get("high")).append(",");
        json.append("\"medium\":").append(summaryMap.get("medium")).append(",");
        json.append("\"low\":").append(summaryMap.get("low"));
        json.append("},");
        
        json.append("\"checks\":[");
        boolean firstCheck = true;
        for (CheckResult check : item.results.getChecks()) {
            if (!firstCheck) json.append(",");
            firstCheck = false;
            json.append("{");
            json.append("\"name\":\"").append(escapeJson(check.getName())).append("\",");
            json.append("\"passed\":").append(check.isPassed()).append(",");
            json.append("\"severity\":\"").append(escapeJson(check.getSeverity())).append("\",");
            json.append("\"issues\":[");
            boolean firstIssue = true;
            for (String issue : check.getIssues()) {
                if (!firstIssue) json.append(",");
                firstIssue = false;
                json.append("\"").append(escapeJson(issue)).append("\"");
            }
            json.append("]");
            json.append("}");
        }
        json.append("],");
        
        json.append("\"issues\":[");
        boolean firstIssue = true;
        for (String issue : item.results.getIssues()) {
            if (!firstIssue) json.append(",");
            firstIssue = false;
            json.append("\"").append(escapeJson(issue)).append("\"");
        }
        json.append("]");
        
        json.append("}");
        return json.toString();
    }

    public static void main(String[] args) {
        try {
            ApiServer apiServer = new ApiServer();
            apiServer.start();
        } catch (IOException e) {
            System.err.println("Failed to start server: " + e.getMessage());
        }
    }
}

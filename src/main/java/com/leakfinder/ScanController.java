package com.leakfinder;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.leakfinder.service.ScanHistoryService;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api")
public class ScanController {

    private final VulnScanner scanner = new VulnScanner();
    private final ScanHistoryService scanHistoryService;
    // VulnScanner prints to System.out. To avoid interleaved output across requests,
    // we keep scanning calls serialized when redirecting stdout.
    private static final Object SCAN_LOCK = new Object();

    public ScanController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @PostMapping("/scan/url")
    public ResponseEntity<?> scanUrl(@RequestBody UrlScanRequest request) {
        String url = request == null ? null : request.getUrl();
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL is required"));
        }

        try {
            ScanResults results;
            synchronized (SCAN_LOCK) {
                results = scanner.scanWebsite(url.trim());
            }

            if (results == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Scan failed - no results returned"));
            }

            scanHistoryService.save(currentUsername(), "URL", url.trim(), results);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage() == null ? "Scan failed" : e.getMessage()));
        }
    }

    @PostMapping("/scan/file")
    public ResponseEntity<?> scanFile(@RequestBody FileScanRequest request) {
        String filePath = request == null ? null : request.getFilePath();
        if (filePath == null || filePath.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "File path is required"));
        }

        try {
            ScanResults results;
            synchronized (SCAN_LOCK) {
                results = scanner.scanFile(filePath.trim());
            }

            if (results == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Scan failed - no results returned"));
            }

            scanHistoryService.save(currentUsername(), "FILE_PATH", filePath.trim(), results);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage() == null ? "Scan failed" : e.getMessage()));
        }
    }

    @PostMapping("/upload/scan")
    public ResponseEntity<?> uploadAndScan(@RequestBody UploadScanRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid request body"));
        }
        if (request.getFileContent() == null || request.getFileContent().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "File content is required"));
        }

        File tempFile = null;
        try {
            String decodedContent;
            if (Boolean.TRUE.equals(request.getIsBase64())) {
                try {
                    byte[] decodedBytes = Base64.getDecoder().decode(request.getFileContent());
                    decodedContent = new String(decodedBytes, StandardCharsets.UTF_8);
                } catch (IllegalArgumentException e) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "Invalid base64 encoding"));
                }
            } else {
                decodedContent = request.getFileContent();
            }

            String extension = "";
            if (request.getFileName() != null && request.getFileName().contains(".")) {
                extension = request.getFileName().substring(request.getFileName().lastIndexOf("."));
            }

            tempFile = File.createTempFile("scan_", extension);
            Files.write(tempFile.toPath(), decodedContent.getBytes(StandardCharsets.UTF_8));

            ScanResults results;
            synchronized (SCAN_LOCK) {
                results = scanner.scanFile(tempFile.getAbsolutePath());
            }

            if (results == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Scan failed - no results returned"));
            }

            String uploadName = request.getFileName() == null ? "upload" : request.getFileName();
            scanHistoryService.save(currentUsername(), "FILE_UPLOAD", uploadName, results);
            return ResponseEntity.ok(results);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to process uploaded file"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage() == null ? "Scan failed" : e.getMessage()));
        } finally {
            if (tempFile != null && tempFile.exists()) {
                // Best-effort cleanup
                //noinspection ResultOfMethodCallIgnored
                tempFile.delete();
            }
        }
    }

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            System.err.println("[ScanController] No authentication context — using 'anonymous'");
            return "anonymous";
        }

        String username = auth.getName();
        if (username == null || "anonymousUser".equalsIgnoreCase(username)) {
            System.err.println("[ScanController] Anonymous user — using 'anonymous' for scan history");
            return "anonymous";
        }

        System.err.println("[ScanController] Authenticated user: " + username);
        return username;
    }

    public static class UrlScanRequest {
        private String url;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    public static class FileScanRequest {
        private String filePath;

        public String getFilePath() {
            return filePath;
        }

        public void setFilePath(String filePath) {
            this.filePath = filePath;
        }
    }

    public static class UploadScanRequest {
        private String fileName;
        private String fileContent;
        private Boolean isBase64;

        public String getFileName() {
            return fileName;
        }

        public void setFileName(String fileName) {
            this.fileName = fileName;
        }

        public String getFileContent() {
            return fileContent;
        }

        public void setFileContent(String fileContent) {
            this.fileContent = fileContent;
        }

        public Boolean getIsBase64() {
            return isBase64;
        }

        public void setIsBase64(Boolean isBase64) {
            this.isBase64 = isBase64;
        }
    }
}


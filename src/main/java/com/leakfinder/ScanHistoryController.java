package com.leakfinder;

import com.fasterxml.jackson.databind.JsonNode;
import com.leakfinder.dto.ScanHistorySummaryResponse;
import com.leakfinder.service.ScanHistoryService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
public class ScanHistoryController {

    private final ScanHistoryService scanHistoryService;

    public ScanHistoryController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping("/history")
    public List<ScanHistorySummaryResponse> history() {
        String username = currentUsername();
        return scanHistoryService.listForUser(username);
    }

    @GetMapping("/history/{id}")
    public JsonNode historyDetails(@PathVariable("id") Long id) {
        String username = currentUsername();
        return scanHistoryService.getResultsForUser(username, id);
    }

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // When not logged in, Spring Security typically uses AnonymousAuthenticationToken
        if (auth == null || auth.getName() == null || "anonymousUser".equalsIgnoreCase(auth.getName())) {
            throw new IllegalStateException("Not authenticated");
        }
        return auth.getName();
    }
}


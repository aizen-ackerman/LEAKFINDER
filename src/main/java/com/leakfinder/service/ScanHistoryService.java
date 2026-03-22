package com.leakfinder.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.leakfinder.dto.ScanHistorySummaryResponse;
import com.leakfinder.model.ScanHistoryEntry;
import com.leakfinder.repository.ScanHistoryRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class ScanHistoryService {

    private final ScanHistoryRepository scanHistoryRepository;
    private final ObjectMapper objectMapper;

    public ScanHistoryService(ScanHistoryRepository scanHistoryRepository, ObjectMapper objectMapper) {
        this.scanHistoryRepository = scanHistoryRepository;
        this.objectMapper = objectMapper;
    }

    public void save(String username, String scanType, String target, Object results) {
        if (results == null) return;

        @SuppressWarnings("unchecked")
        Map<String, Integer> summary = extractSummary(results);
        ScanHistoryEntry entry = new ScanHistoryEntry();
        entry.setUsername(username);
        entry.setScanType(scanType);
        entry.setTarget(target);
        entry.setScannedAt(LocalDateTime.now());

        entry.setTotal(get(summary, "total"));
        entry.setPassed(get(summary, "passed"));
        entry.setFailed(get(summary, "failed"));
        entry.setHigh(get(summary, "high"));
        entry.setMedium(get(summary, "medium"));
        entry.setLow(get(summary, "low"));

        try {
            // Store full results so frontend can render the same structure later.
            entry.setResultsJson(objectMapper.writeValueAsString(results));
        } catch (Exception e) {
            // As a fallback, still save the entry (without results JSON) to avoid losing scan metadata.
            entry.setResultsJson("{\"error\":\"failed_to_serialize_scan_results\"}");
        }

        scanHistoryRepository.save(entry);
    }

    public List<ScanHistorySummaryResponse> listForUser(String username) {
        return scanHistoryRepository.findTop20ByUsernameOrderByScannedAtDesc(username).stream()
                .map(e -> {
                    ScanHistorySummaryResponse r = new ScanHistorySummaryResponse();
                    r.setId(e.getId());
                    r.setScanType(e.getScanType());
                    r.setTarget(e.getTarget());
                    r.setScannedAt(e.getScannedAt());
                    r.setTotal(e.getTotal());
                    r.setPassed(e.getPassed());
                    r.setFailed(e.getFailed());
                    r.setHigh(e.getHigh());
                    r.setMedium(e.getMedium());
                    r.setLow(e.getLow());
                    return r;
                })
                .collect(Collectors.toList());
    }

    public JsonNode getResultsForUser(String username, Long id) {
        ScanHistoryEntry entry = scanHistoryRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found"));
        if (!Objects.equals(entry.getUsername(), username)) {
            throw new IllegalArgumentException("Scan not found");
        }

        try {
            return objectMapper.readTree(entry.getResultsJson());
        } catch (Exception e) {
            return objectMapper.createObjectNode().put("error", "failed_to_parse_saved_results");
        }
    }

    private int get(Map<String, Integer> summary, String key) {
        Integer v = summary == null ? null : summary.get(key);
        return v == null ? 0 : v;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Integer> extractSummary(Object results) {
        try {
            // ScanResults class is package-private, so we use reflection.
            Object summaryObj = results.getClass().getMethod("getSummary").invoke(results);
            if (summaryObj instanceof Map) return (Map<String, Integer>) summaryObj;
        } catch (Exception ignored) {
        }
        return Map.of();
    }
}


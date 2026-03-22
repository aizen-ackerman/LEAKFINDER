package com.leakfinder.repository;

import com.leakfinder.model.ScanHistoryEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanHistoryRepository extends JpaRepository<ScanHistoryEntry, Long> {
    List<ScanHistoryEntry> findTop20ByUsernameOrderByScannedAtDesc(String username);
}


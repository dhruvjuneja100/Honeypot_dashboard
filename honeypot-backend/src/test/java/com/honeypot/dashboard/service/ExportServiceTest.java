package com.honeypot.dashboard.service;

import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.repository.AttackLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ExportServiceTest {

    @Mock
    private AttackLogRepository attackLogRepository;

    @InjectMocks
    private ExportService exportService;

    @Test
    public void testExportToCsv() throws Exception {
        AttackLog log = new AttackLog();
        log.setId(1L);
        log.setIpAddress("10.0.0.1");
        log.setAttackType("SQL Injection");
        log.setTimestamp(LocalDateTime.now());
        
        when(attackLogRepository.findAll()).thenReturn(Collections.singletonList(log));

        byte[] csvBytes = exportService.exportToCsv();
        assertNotNull(csvBytes);
        assertTrue(csvBytes.length > 0);
        String csvContent = new String(csvBytes);
        assertTrue(csvContent.contains("SQL Injection"));
        assertTrue(csvContent.contains("10.0.0.1"));
    }

    @Test
    public void testExportToPdf() throws Exception {
        AttackLog log = new AttackLog();
        log.setId(1L);
        log.setIpAddress("10.0.0.1");
        log.setAttackType("SQL Injection");
        log.setTimestamp(LocalDateTime.now());
        log.setThreatScore(90);
        
        when(attackLogRepository.findAll()).thenReturn(Collections.singletonList(log));

        byte[] pdfBytes = exportService.exportToPdf();
        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 0);
        // PDF is a binary format, so we can't easily assert plain text content, 
        // but verifying it produced output bytes is a good sanity check.
    }
}

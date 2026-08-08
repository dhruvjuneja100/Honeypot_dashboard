package com.honeypot.dashboard.controller;

import com.honeypot.dashboard.service.AnalyticsService;
import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.service.ExportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    @Autowired
    private AnalyticsService analyticsService;

    @Autowired
    private ExportService exportService;

    @GetMapping("/attacksByType")
    public List<Map<String, Object>> getAttacksByType() {
        return analyticsService.getAttacksByType();
    }

    @GetMapping("/topIPs")
    public List<Map<String, Object>> getTopIps() {
        return analyticsService.getTopIps();
    }

    @GetMapping("/geoDistribution")
    public List<Map<String, Object>> getGeoDistribution() {
        return analyticsService.getGeoDistribution();
    }

    @GetMapping({"/logs", "/attacks"})
    public Page<Map<String, Object>> getLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return analyticsService.getRecentLogs(page, size);
    }

    @GetMapping("/export/csv")
    public ResponseEntity<byte[]> exportCsv() throws Exception {
        byte[] csvData = exportService.exportToCsv();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=honeypot-logs.csv")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csvData);
    }

    @GetMapping("/export/pdf")
    public ResponseEntity<byte[]> exportPdf() throws Exception {
        byte[] pdfData = exportService.exportToPdf();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=honeypot-logs.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfData);
    }
}

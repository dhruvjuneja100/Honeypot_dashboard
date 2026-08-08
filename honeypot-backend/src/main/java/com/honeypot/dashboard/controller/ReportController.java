package com.honeypot.dashboard.controller;

import com.honeypot.dashboard.model.Alert;
import com.honeypot.dashboard.service.ReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class ReportController {

    @Autowired
    private ReportService reportService;

    @GetMapping("/api/reports/summary")
    public ResponseEntity<Map<String, Object>> getSummary() {
        return ResponseEntity.ok(reportService.getSummary());
    }

    @GetMapping("/api/reports/alerts")
    public ResponseEntity<List<Alert>> getAlerts() {
        return ResponseEntity.ok(reportService.getAlerts());
    }

    @GetMapping("/api/reports/export")
    public ResponseEntity<byte[]> exportReport(@RequestParam(name = "format", defaultValue = "csv") String format) {
        try {
            if ("pdf".equalsIgnoreCase(format)) {
                byte[] pdfBytes = reportService.exportToPdf();
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_PDF);
                headers.setContentDispositionFormData("attachment", "alerts_report.pdf");
                return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
            } else {
                byte[] csvBytes = reportService.exportToCsv();
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.parseMediaType("text/csv"));
                headers.setContentDispositionFormData("attachment", "alerts_report.csv");
                return new ResponseEntity<>(csvBytes, headers, HttpStatus.OK);
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}

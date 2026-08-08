package com.honeypot.dashboard.service;

import com.honeypot.dashboard.model.Alert;
import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.repository.AlertRepository;
import com.honeypot.dashboard.repository.AttackLogRepository;
import com.opencsv.CSVWriter;
import com.lowagie.text.Document;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ReportService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired
    private AlertRepository alertRepository;

    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("totalAttacks", attackLogRepository.count());

        // Convert top IPs to proper map list
        List<Map<String, Object>> topIpsList = new java.util.ArrayList<>();
        for (Object[] row : attackLogRepository.findTop10Ips()) {
            Map<String, Object> entry = new java.util.LinkedHashMap<>();
            entry.put("ip", row[0]);
            entry.put("count", row[1]);
            topIpsList.add(entry);
        }
        summary.put("topIps", topIpsList);

        // Convert attack types to proper map list
        List<Map<String, Object>> attackTypesList = new java.util.ArrayList<>();
        for (Object[] row : attackLogRepository.countAttacksByType()) {
            Map<String, Object> entry = new java.util.LinkedHashMap<>();
            entry.put("type", row[0]);
            entry.put("count", row[1]);
            attackTypesList.add(entry);
        }
        summary.put("topAttackTypes", attackTypesList);

        return summary;
    }

    public List<Alert> getAlerts() {
        return alertRepository.findAllByOrderByTimestampDesc();
    }

    public byte[] exportToCsv() throws Exception {
        List<Alert> alerts = alertRepository.findAllByOrderByTimestampDesc();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (CSVWriter writer = new CSVWriter(new OutputStreamWriter(baos))) {
            String[] header = {"ID", "Attack Type", "IP Address", "Threat Score", "Timestamp"};
            writer.writeNext(header);
            
            for (Alert alert : alerts) {
                String ip = alert.getAttackLog() != null ? alert.getAttackLog().getIpAddress() : "Unknown";
                String[] row = {
                    String.valueOf(alert.getId()),
                    alert.getAlertType(),
                    ip,
                    String.valueOf(alert.getThreatScore()),
                    alert.getTimestamp().toString()
                };
                writer.writeNext(row);
            }
        }
        return baos.toByteArray();
    }

    public byte[] exportToPdf() throws Exception {
        List<Alert> alerts = alertRepository.findAllByOrderByTimestampDesc();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        Document document = new Document();
        PdfWriter.getInstance(document, baos);
        document.open();
        
        document.add(new Paragraph("Honeypot Alerts Report"));
        document.add(new Paragraph(" "));
        
        for (Alert alert : alerts) {
            String ip = alert.getAttackLog() != null ? alert.getAttackLog().getIpAddress() : "Unknown";
            String line = String.format("ID: %d | Type: %s | IP: %s | Score: %d | Time: %s",
                    alert.getId(), alert.getAlertType(), ip, alert.getThreatScore(), alert.getTimestamp());
            document.add(new Paragraph(line));
        }
        
        document.close();
        return baos.toByteArray();
    }
}

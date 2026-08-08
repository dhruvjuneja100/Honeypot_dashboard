package com.honeypot.dashboard.service;

import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.repository.AttackLogRepository;
import com.lowagie.text.Document;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;
import com.opencsv.CSVWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.util.List;

@Service
public class ExportService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    public byte[] exportToCsv() throws Exception {
        List<AttackLog> logs = attackLogRepository.findAll();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CSVWriter writer = new CSVWriter(new OutputStreamWriter(out));

        // Header
        writer.writeNext(new String[]{"ID", "Timestamp", "IP Address", "Attack Type", "Endpoint", "Country", "City", "Threat Score"});

        // Data
        for (AttackLog log : logs) {
            writer.writeNext(new String[]{
                    String.valueOf(log.getId()),
                    log.getTimestamp() != null ? log.getTimestamp().toString() : "",
                    log.getIpAddress(),
                    log.getAttackType(),
                    log.getEndpoint(),
                    log.getCountry(),
                    log.getCity(),
                    String.valueOf(log.getThreatScore())
            });
        }
        writer.close();
        return out.toByteArray();
    }

    public byte[] exportToPdf() throws Exception {
        List<AttackLog> logs = attackLogRepository.findAll();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document();
        PdfWriter.getInstance(document, out);

        document.open();
        document.add(new Paragraph("Honeypot Attack Logs Report"));
        document.add(new Paragraph("Total Attacks: " + logs.size()));
        document.add(new Paragraph(" "));

        for (AttackLog log : logs) {
            String line = String.format("[%s] %s - %s on %s (Threat: %d)",
                    log.getTimestamp(), log.getIpAddress(), log.getAttackType(), log.getEndpoint(), log.getThreatScore());
            document.add(new Paragraph(line));
        }

        document.close();
        return out.toByteArray();
    }
}

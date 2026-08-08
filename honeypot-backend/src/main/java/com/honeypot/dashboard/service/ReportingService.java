package com.honeypot.dashboard.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class ReportingService {

    @Autowired
    private AnalyticsService analyticsService;

    @Autowired
    private AlertService alertService;

    // Run every Sunday at midnight
    @Scheduled(cron = "0 0 0 * * SUN")
    public void generateWeeklyReport() {
        System.out.println("Generating Weekly Report...");
        List<Map<String, Object>> topIps = analyticsService.getTopIps();
        List<Map<String, Object>> attacksByType = analyticsService.getAttacksByType();

        StringBuilder report = new StringBuilder();
        report.append("Weekly Honeypot Summary\n\n");
        report.append("Top Attacking IPs:\n");
        for (Map<String, Object> entry : topIps) {
            report.append(" - ").append(entry.get("ip")).append(": ").append(entry.get("count")).append("\n");
        }
        
        report.append("\nAttacks by Type:\n");
        for (Map<String, Object> entry : attacksByType) {
            report.append(" - ").append(entry.get("type")).append(": ").append(entry.get("count")).append("\n");
        }

        // We can reuse the alert service to send the report
        // alertService.sendEmailAlert("Weekly Honeypot Report", report.toString());
        System.out.println(report.toString());
    }
}

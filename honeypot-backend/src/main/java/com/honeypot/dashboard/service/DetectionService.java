package com.honeypot.dashboard.service;

import com.honeypot.dashboard.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.regex.Pattern;

@Service
public class DetectionService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    private static final Pattern SQLI_PATTERN = Pattern.compile("(?i)(SELECT.*FROM|DROP\\s+TABLE|INSERT\\s+INTO|UPDATE.*SET|UNION\\s+ALL|UNION\\s+SELECT|['\"].*?(?:OR|AND).*?['\"].*?=.*|['\"].*?--|['\"].*?#)");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i)(<script.*?>.*?<\\/script>|onerror=|onload=|javascript:|alert\\()");
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile("(?i)(\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c|\\/etc\\/passwd|\\/windows\\/win\\.ini)");
    private static final Pattern MALICIOUS_UPLOAD_PATTERN = Pattern.compile("(?i)(\\.exe|\\.js|\\.vbs|\\.bat|\\.sh|\\.php)$");

    public String classifyAttack(String ipAddress, String endpoint, String payload) {
        if (payload != null) {
            if (SQLI_PATTERN.matcher(payload).find()) {
                return "SQL_INJECTION";
            }
            if (XSS_PATTERN.matcher(payload).find()) {
                return "XSS";
            }
            if (PATH_TRAVERSAL_PATTERN.matcher(payload).find()) {
                return "PATH_TRAVERSAL";
            }
        }

        if (endpoint != null) {
            if (PATH_TRAVERSAL_PATTERN.matcher(endpoint).find()) {
                return "PATH_TRAVERSAL";
            }
            if (endpoint.contains("/upload") && payload != null && MALICIOUS_UPLOAD_PATTERN.matcher(payload).find()) {
                return "MALICIOUS_UPLOAD";
            }
        }

        // Check for Brute Force (e.g. > 10 requests from same IP in last 5 minutes)
        if (endpoint != null && endpoint.contains("/login")) {
            LocalDateTime fiveMinutesAgo = LocalDateTime.now().minusMinutes(5);
            int recentAttempts = attackLogRepository.countByIpAddressAndEndpointAndTimestampAfter(ipAddress, endpoint, fiveMinutesAgo);
            if (recentAttempts > 10) {
                return "BRUTE_FORCE";
            }
        }

        return "UNKNOWN";
    }
}

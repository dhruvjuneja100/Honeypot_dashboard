package com.honeypot.dashboard.service;

import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AnalyticsService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    private String formatAttackType(String type) {
        if (type == null) return "Unknown";
        switch (type.trim().toUpperCase()) {
            case "SQL_INJECTION": return "SQL Injection";
            case "XSS": return "Cross-Site Scripting";
            case "PATH_TRAVERSAL": return "Path Traversal";
            case "BRUTE_FORCE": return "Brute Force";
            case "COMMAND_INJECTION": return "Command Injection";
            case "MALICIOUS_UPLOAD":
            case "MALICIOUS_FILE_UPLOAD": return "Malicious Upload";
            case "UNKNOWN": return "Unknown";
            default: return type.trim();
        }
    }

    public List<Map<String, Object>> getAttacksByType() {
        Map<String, Long> aggregated = new LinkedHashMap<>();
        for (Object[] row : attackLogRepository.countAttacksByType()) {
            String rawType = (String) row[0];
            Long count = (Long) row[1];
            // A single DB row may have a comma-separated multi-attack string; split and count each
            if (rawType != null && rawType.contains(",")) {
                for (String part : rawType.split(",\\s*")) {
                    String formatted = formatAttackType(part);
                    aggregated.put(formatted, aggregated.getOrDefault(formatted, 0L) + count);
                }
            } else {
                String formattedType = formatAttackType(rawType);
                aggregated.put(formattedType, aggregated.getOrDefault(formattedType, 0L) + count);
            }
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, Long> entry : aggregated.entrySet()) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("type", entry.getKey());
            map.put("count", entry.getValue());
            result.add(map);
        }
        return result;
    }

    public List<Map<String, Object>> getTopIps() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object[] row : attackLogRepository.findTop10Ips()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("ip", row[0]);
            entry.put("count", row[1]);
            result.add(entry);
        }
        return result;
    }

    public List<Map<String, Object>> getGeoDistribution() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object[] row : attackLogRepository.countGeoDistribution()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("country", row[0]);
            entry.put("city", row[1]);
            entry.put("count", row[2]);
            result.add(entry);
        }
        return result;
    }

    public Page<Map<String, Object>> getRecentLogs(int page, int size) {
        Page<AttackLog> logs = attackLogRepository.findAll(PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp")));
        return logs.map(log -> {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", log.getId());
            map.put("timestamp", log.getTimestamp());
            map.put("ipAddress", log.getIpAddress());
            map.put("attackType", log.getAttackType() != null
                    ? String.join(", ", java.util.Arrays.stream(log.getAttackType().split(",\\s*"))
                        .map(this::formatAttackType)
                        .toArray(String[]::new))
                    : "Unknown");
            map.put("endpoint", log.getEndpoint());
            map.put("country", log.getCountry());
            map.put("city", log.getCity());
            map.put("latitude", log.getLatitude());
            map.put("longitude", log.getLongitude());
            map.put("threatScore", log.getThreatScore());
            return map;
        });
    }
}

package com.honeypot.dashboard.service;

import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class LoggingService {

    @Autowired
    private AttackLogRepository attackLogRepository;

    @Autowired
    private EnrichmentService enrichmentService;

    @Autowired
    private org.springframework.context.ApplicationEventPublisher eventPublisher;

    @Async
    public void saveAttackLog(AttackLog attackLog) {
        // Enrich IP data
        if (attackLog.getIpAddress() != null) {
            EnrichmentService.EnrichedIpData enrichedData = enrichmentService.enrichIp(attackLog.getIpAddress());
            attackLog.setCountry(enrichedData.country);
            attackLog.setCity(enrichedData.city);
            attackLog.setLatitude(enrichedData.latitude);
            attackLog.setLongitude(enrichedData.longitude);
            int externalScore = enrichedData.threatScore != null ? enrichedData.threatScore : 0;
            int baselineScore = getBaselineScore(attackLog.getAttackType());
            attackLog.setThreatScore(Math.max(externalScore, baselineScore));
        }

        AttackLog savedLog = attackLogRepository.save(attackLog);
        eventPublisher.publishEvent(new com.honeypot.dashboard.model.AttackLoggedEvent(this, savedLog));
    }

    private int getBaselineScore(String attackType) {
        if (attackType == null || attackType.isEmpty()) return 20;

        int maxScore = 20;
        String[] types = attackType.split(",\\s*");
        for (String type : types) {
            int score = 20;
            switch (type.trim()) {
                case "MALICIOUS_UPLOAD": score = 90; break;
                case "SQL_INJECTION": score = 80; break;
                case "COMMAND_INJECTION": score = 75; break;
                case "BRUTE_FORCE": score = 70; break;
                case "XSS": score = 65; break;
                case "PATH_TRAVERSAL": score = 60; break;
                default: score = 20; break;
            }
            if (score > maxScore) {
                maxScore = score;
            }
        }
        return maxScore;
    }
}

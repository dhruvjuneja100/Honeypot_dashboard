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
        if (attackType == null) return 20;
        switch (attackType) {
            case "SQL_INJECTION": return 80;
            case "BRUTE_FORCE": return 70;
            case "PATH_TRAVERSAL": return 60;
            case "MALICIOUS_UPLOAD": return 90;
            case "XSS": return 65;
            default: return 20;
        }
    }
}

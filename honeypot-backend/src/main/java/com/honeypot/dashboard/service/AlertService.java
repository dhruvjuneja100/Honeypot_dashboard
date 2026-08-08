package com.honeypot.dashboard.service;

import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.model.AttackLoggedEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.Map;

@Service
public class AlertService {

    // Uncomment and inject when mail server properties are configured
    // @Autowired
    // private JavaMailSender mailSender;

    @Value("${honeypot.alert.email.to:admin@example.com}")
    private String alertEmailTo;

    @Value("${honeypot.alert.slack.webhook:}")
    private String slackWebhookUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    private com.honeypot.dashboard.repository.AlertRepository alertRepository;

    @Async
    @EventListener
    public void handleAttackLoggedEvent(AttackLoggedEvent event) {
        AttackLog log = event.getAttackLog();
        
        // Trigger alert for high severity attacks
        String attackType = log.getAttackType() != null ? log.getAttackType() : "";
        if (attackType.contains("SQL_INJECTION") || attackType.contains("XSS") ||
            attackType.contains("BRUTE_FORCE") || attackType.contains("MALICIOUS_UPLOAD") ||
            attackType.contains("COMMAND_INJECTION") || attackType.contains("PATH_TRAVERSAL") ||
            (log.getThreatScore() != null && log.getThreatScore() >= 80)) {
            
            // Save to DB
            com.honeypot.dashboard.model.Alert alert = new com.honeypot.dashboard.model.Alert(log, log.getAttackType(), log.getThreatScore());
            alertRepository.save(alert);
            
            String message = String.format("🚨 High Severity Attack Detected!\nType: %s\nIP: %s\nLocation: %s, %s\nPayload: %s",
                    log.getAttackType(), log.getIpAddress(), log.getCity(), log.getCountry(), log.getPayload());
            
            sendSlackAlert(message);
            // sendEmailAlert("Honeypot Alert - " + log.getAttackType(), message);
        }
    }

    private void sendSlackAlert(String message) {
        if (slackWebhookUrl != null && !slackWebhookUrl.isEmpty()) {
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<Map<String, String>> request = new HttpEntity<>(Map.of("text", message), headers);
                restTemplate.postForEntity(slackWebhookUrl, request, String.class);
            } catch (Exception e) {
                System.err.println("Failed to send Slack alert: " + e.getMessage());
            }
        } else {
            System.out.println("SLACK ALERT (Mock): " + message);
        }
    }

    private void sendEmailAlert(String subject, String text) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(alertEmailTo);
            message.setSubject(subject);
            message.setText(text);
            // mailSender.send(message);
            System.out.println("EMAIL ALERT (Mock): " + subject);
        } catch (Exception e) {
            System.err.println("Failed to send Email alert: " + e.getMessage());
        }
    }
}

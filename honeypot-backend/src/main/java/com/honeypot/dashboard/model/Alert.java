package com.honeypot.dashboard.model;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.LocalDateTime;

@Entity
@Table(name = "alerts")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "attack_log_id", nullable = false)
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
    private AttackLog attackLog;

    @Column(name = "alert_type")
    private String alertType;

    @Column(name = "threat_score")
    private Integer threatScore;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    public Alert() {
        this.timestamp = LocalDateTime.now();
    }

    public Alert(AttackLog attackLog, String alertType, Integer threatScore) {
        this.attackLog = attackLog;
        this.alertType = alertType;
        this.threatScore = threatScore;
        this.timestamp = LocalDateTime.now();
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public AttackLog getAttackLog() {
        return attackLog;
    }

    public void setAttackLog(AttackLog attackLog) {
        this.attackLog = attackLog;
    }

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public Integer getThreatScore() {
        return threatScore;
    }

    public void setThreatScore(Integer threatScore) {
        this.threatScore = threatScore;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}

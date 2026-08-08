package com.honeypot.dashboard.model;

import org.springframework.context.ApplicationEvent;

public class AttackLoggedEvent extends ApplicationEvent {
    private final AttackLog attackLog;

    public AttackLoggedEvent(Object source, AttackLog attackLog) {
        super(source);
        this.attackLog = attackLog;
    }

    public AttackLog getAttackLog() {
        return attackLog;
    }
}

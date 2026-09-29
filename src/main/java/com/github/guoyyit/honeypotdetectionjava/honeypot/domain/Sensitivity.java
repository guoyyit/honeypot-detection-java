package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

public enum Sensitivity {
    LOW,
    MEDIUM,
    HIGH;

    public AlertLevel toAlertLevel() {
        return switch (this) {
            case LOW -> AlertLevel.INFO;
            case MEDIUM -> AlertLevel.WARNING;
            case HIGH -> AlertLevel.CRITICAL;
        };
    }
}

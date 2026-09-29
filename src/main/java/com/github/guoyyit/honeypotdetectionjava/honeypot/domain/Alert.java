package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

/**
 * An alert aggregating touches of one decoy from one source.
 * Repeated touches within the cooldown window only upgrade this alert.
 */
public class Alert {
    public String id;
    public String decoyId;
    public DecoyType decoyType;
    public String source;
    public AlertLevel level = AlertLevel.WARNING;
    public AlertStatus status = AlertStatus.OPEN;
    public int touchCount;
    public long firstTouchAt;
    public long lastTouchAt;
    public long updatedAt;
}

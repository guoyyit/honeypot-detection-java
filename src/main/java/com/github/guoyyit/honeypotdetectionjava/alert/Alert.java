package com.github.guoyyit.honeypotdetectionjava.alert;

import com.github.guoyyit.honeypotdetectionjava.decoy.AlertSeverity;
import com.github.guoyyit.honeypotdetectionjava.decoy.AlertState;

public class Alert {
    private String id;
    private String decoyId;
    private String sourceIp;
    private AlertSeverity severity;
    private AlertState state = AlertState.OPEN;
    private long firstEventAt;
    private long lastEventAt;
    private long lastNotifiedAt;
    private int touchCount;
    private String lastEventId;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDecoyId() {
        return decoyId;
    }

    public void setDecoyId(String decoyId) {
        this.decoyId = decoyId;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public AlertSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(AlertSeverity severity) {
        this.severity = severity;
    }

    public AlertState getState() {
        return state;
    }

    public void setState(AlertState state) {
        this.state = state;
    }

    public long getFirstEventAt() {
        return firstEventAt;
    }

    public void setFirstEventAt(long firstEventAt) {
        this.firstEventAt = firstEventAt;
    }

    public long getLastEventAt() {
        return lastEventAt;
    }

    public void setLastEventAt(long lastEventAt) {
        this.lastEventAt = lastEventAt;
    }

    public long getLastNotifiedAt() {
        return lastNotifiedAt;
    }

    public void setLastNotifiedAt(long lastNotifiedAt) {
        this.lastNotifiedAt = lastNotifiedAt;
    }

    public int getTouchCount() {
        return touchCount;
    }

    public void setTouchCount(int touchCount) {
        this.touchCount = touchCount;
    }

    public String getLastEventId() {
        return lastEventId;
    }

    public void setLastEventId(String lastEventId) {
        this.lastEventId = lastEventId;
    }
}

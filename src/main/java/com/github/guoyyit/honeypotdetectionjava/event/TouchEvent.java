package com.github.guoyyit.honeypotdetectionjava.event;

import com.github.guoyyit.honeypotdetectionjava.decoy.TouchKind;

public class TouchEvent {
    private String eventId;
    private String decoyId;
    private TouchKind kind;
    private String sourceIp;
    private String userAgent;
    private String requestPath;
    private long timestamp;
    private boolean exempted;
    private String matchedExemptionId;
    private Boolean passwordMatched;
    private boolean processed;

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getDecoyId() {
        return decoyId;
    }

    public void setDecoyId(String decoyId) {
        this.decoyId = decoyId;
    }

    public TouchKind getKind() {
        return kind;
    }

    public void setKind(TouchKind kind) {
        this.kind = kind;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public void setRequestPath(String requestPath) {
        this.requestPath = requestPath;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public boolean isExempted() {
        return exempted;
    }

    public void setExempted(boolean exempted) {
        this.exempted = exempted;
    }

    public String getMatchedExemptionId() {
        return matchedExemptionId;
    }

    public void setMatchedExemptionId(String matchedExemptionId) {
        this.matchedExemptionId = matchedExemptionId;
    }

    public Boolean getPasswordMatched() {
        return passwordMatched;
    }

    public void setPasswordMatched(Boolean passwordMatched) {
        this.passwordMatched = passwordMatched;
    }

    public boolean isProcessed() {
        return processed;
    }

    public void setProcessed(boolean processed) {
        this.processed = processed;
    }
}

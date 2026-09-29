package com.github.guoyyit.honeypotdetectionjava.persist;

import com.github.guoyyit.honeypotdetectionjava.alert.Alert;
import com.github.guoyyit.honeypotdetectionjava.audit.AuditEntry;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyResource;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionRule;

import java.util.ArrayList;
import java.util.List;

public class PersistentState {
    private List<DecoyResource> decoys = new ArrayList<>();
    private List<TouchEvent> touchEvents = new ArrayList<>();
    private List<Alert> alerts = new ArrayList<>();
    private List<ExemptionRule> exemptionRules = new ArrayList<>();
    private List<AuditEntry> auditEntries = new ArrayList<>();

    public List<DecoyResource> getDecoys() {
        return decoys;
    }

    public void setDecoys(List<DecoyResource> decoys) {
        this.decoys = decoys;
    }

    public List<TouchEvent> getTouchEvents() {
        return touchEvents;
    }

    public void setTouchEvents(List<TouchEvent> touchEvents) {
        this.touchEvents = touchEvents;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }

    public void setAlerts(List<Alert> alerts) {
        this.alerts = alerts;
    }

    public List<ExemptionRule> getExemptionRules() {
        return exemptionRules;
    }

    public void setExemptionRules(List<ExemptionRule> exemptionRules) {
        this.exemptionRules = exemptionRules;
    }

    public List<AuditEntry> getAuditEntries() {
        return auditEntries;
    }

    public void setAuditEntries(List<AuditEntry> auditEntries) {
        this.auditEntries = auditEntries;
    }
}

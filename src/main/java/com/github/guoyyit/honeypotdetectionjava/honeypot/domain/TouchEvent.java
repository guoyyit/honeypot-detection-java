package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

/**
 * A recorded touch of a decoy resource. Persisted before processing so restarts lose nothing.
 * Exempted touches are still stored as evidence ({@link #exempted}) but never raise alerts.
 */
public class TouchEvent {
    public String id;
    public String decoyId;
    public DecoyType decoyType;
    public Sensitivity sensitivity = Sensitivity.MEDIUM;
    public String source;
    public long occurredAt;
    public String detail;
    public boolean exempted;
    public String exemptionRuleId;
}

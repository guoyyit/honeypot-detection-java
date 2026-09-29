package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

/**
 * An audit trail entry for management operations.
 */
public class AuditRecord {
    public String id;
    public String operator;
    public String action;
    public String targetType;
    public String targetId;
    public String detail;
    public long occurredAt;
}

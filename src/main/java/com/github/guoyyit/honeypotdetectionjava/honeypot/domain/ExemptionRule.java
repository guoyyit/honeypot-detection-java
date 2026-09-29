package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

/**
 * An exemption rule for known-benign traffic (health checks, management, internal jobs).
 */
public class ExemptionRule {
    public String id;
    public String name;
    public ExemptionType type = ExemptionType.SOURCE_IP_PREFIX;
    public String pattern;
    public boolean enabled = true;
    public long createdAt;
    public long updatedAt;
}

package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

/**
 * A decoy HTTP endpoint. Any request to {@link #path} while ENABLED is an attack signal.
 */
public class DecoyEndpoint {
    public String id;
    public String path;
    public DecoyStatus status = DecoyStatus.ENABLED;
    public Sensitivity sensitivity = Sensitivity.MEDIUM;
    public int responseStatus = 200;
    public String contentType = "application/json";
    public String responseBody = "{}";
    public long createdAt;
    public long updatedAt;
}

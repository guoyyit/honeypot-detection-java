package com.github.guoyyit.honeypotdetectionjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "honeypot")
public class HoneypotProperties {
    private String adminToken = "";
    private String stateFile = "";
    private long alertCooldownMillis = 0L;
    private String internalMarker = "";
    private String healthPath = "";
    private String internalProbeBaseUrl = "";

    public String getAdminToken() {
        return adminToken;
    }

    public void setAdminToken(String adminToken) {
        this.adminToken = adminToken;
    }

    public String getStateFile() {
        return stateFile;
    }

    public void setStateFile(String stateFile) {
        this.stateFile = stateFile;
    }

    public long getAlertCooldownMillis() {
        return alertCooldownMillis;
    }

    public void setAlertCooldownMillis(long alertCooldownMillis) {
        this.alertCooldownMillis = alertCooldownMillis;
    }

    public String getInternalMarker() {
        return internalMarker;
    }

    public void setInternalMarker(String internalMarker) {
        this.internalMarker = internalMarker;
    }

    public String getHealthPath() {
        return healthPath;
    }

    public void setHealthPath(String healthPath) {
        this.healthPath = healthPath;
    }

    public String getInternalProbeBaseUrl() {
        return internalProbeBaseUrl;
    }

    public void setInternalProbeBaseUrl(String internalProbeBaseUrl) {
        this.internalProbeBaseUrl = internalProbeBaseUrl;
    }
}

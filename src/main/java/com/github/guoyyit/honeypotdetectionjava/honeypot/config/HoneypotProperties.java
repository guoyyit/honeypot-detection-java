package com.github.guoyyit.honeypotdetectionjava.honeypot.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "honeypot")
public class HoneypotProperties {
    /** Directory for persistent state (decoys, events, alerts, exemptions, audit). */
    private String dataDir = "./honeypot-data";
    /** Token required in the X-Admin-Token header for management API calls. */
    private String adminToken = "change-me";
    /** Cooldown window in milliseconds for alert de-duplication. */
    private long alertCooldownMillis = 300_000;
    /** Path prefix of the management API; decoys may not shadow it. */
    private String adminPathPrefix = "/api/honeypot";
    /** Demo legitimate users (username -> password) for the sample login endpoint. */
    private Map<String, String> legitUsers = new LinkedHashMap<>();

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public String getAdminToken() {
        return adminToken;
    }

    public void setAdminToken(String adminToken) {
        this.adminToken = adminToken;
    }

    public long getAlertCooldownMillis() {
        return alertCooldownMillis;
    }

    public void setAlertCooldownMillis(long alertCooldownMillis) {
        this.alertCooldownMillis = alertCooldownMillis;
    }

    public String getAdminPathPrefix() {
        return adminPathPrefix;
    }

    public void setAdminPathPrefix(String adminPathPrefix) {
        this.adminPathPrefix = adminPathPrefix;
    }

    public Map<String, String> getLegitUsers() {
        return legitUsers;
    }

    public void setLegitUsers(Map<String, String> legitUsers) {
        this.legitUsers = legitUsers;
    }
}

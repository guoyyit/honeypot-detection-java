package com.github.guoyyit.honeypotdetectionjava.web;

public class AccessContext {
    private final String sourceIp;
    private final String userAgent;
    private final String path;

    public AccessContext(String sourceIp, String userAgent, String path) {
        this.sourceIp = sourceIp;
        this.userAgent = userAgent;
        this.path = path;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getPath() {
        return path;
    }
}

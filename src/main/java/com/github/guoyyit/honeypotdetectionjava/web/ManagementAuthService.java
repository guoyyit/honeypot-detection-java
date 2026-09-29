package com.github.guoyyit.honeypotdetectionjava.web;

import com.github.guoyyit.honeypotdetectionjava.audit.AuditService;
import com.github.guoyyit.honeypotdetectionjava.config.HoneypotProperties;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Service
public class ManagementAuthService {

    public static final String TOKEN_HEADER = "X-Admin-Token";
    public static final String ACTOR_HEADER = "X-Admin-Actor";

    private final HoneypotProperties properties;
    private final AuditService auditService;

    public ManagementAuthService(HoneypotProperties properties, AuditService auditService) {
        this.properties = properties;
        this.auditService = auditService;
    }

    public String authenticate(String adminToken, String actor) {
        String expected = properties.getAdminToken();
        if (expected == null || expected.isBlank() || adminToken == null
                || !constantTimeEquals(expected, adminToken)) {
            auditService.record(actor != null ? actor : "anonymous",
                    "ADMIN_AUTH_FAILURE", "ManagementApi", null,
                    "invalid or missing admin token", false);
            return null;
        }
        return actor != null && !actor.isBlank() ? actor : "admin";
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}

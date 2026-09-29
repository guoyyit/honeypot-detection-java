package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import com.github.guoyyit.honeypotdetectionjava.honeypot.config.HoneypotProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Verifies the admin token on management API calls using a constant-time comparison.
 */
public class AdminAuthInterceptor implements HandlerInterceptor {

    public static final String ADMIN_TOKEN_HEADER = "X-Admin-Token";

    private final HoneypotProperties properties;

    public AdminAuthInterceptor(HoneypotProperties properties) {
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String token = request.getHeader(ADMIN_TOKEN_HEADER);
        if (token != null && constantTimeEquals(token, properties.getAdminToken())) {
            return true;
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"missing or invalid admin token\"}");
        return false;
    }

    private boolean constantTimeEquals(String a, String b) {
        if (b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}

package com.github.guoyyit.honeypotdetectionjava.web;

import com.github.guoyyit.honeypotdetectionjava.decoy.CredentialDetectionService;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEvent;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    private final CredentialDetectionService credentialDetectionService;

    public LoginController(CredentialDetectionService credentialDetectionService) {
        this.credentialDetectionService = credentialDetectionService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String username = body.get("username");
        String password = body.get("password");
        String sourceIp = resolveSourceIp(request);
        String userAgent = request.getHeader("User-Agent");
        TouchEvent touch = credentialDetectionService.detect(username, password,
                new AccessContext(sourceIp, userAgent, request.getRequestURI()),
                CatchAllDecoyController.MONITORING_HEADER,
                request.getHeader(CatchAllDecoyController.MONITORING_HEADER));
        if (touch != null) {
            log.warn("Decoy credential usage detected: eventId={} decoyId={} sourceIp={}",
                    touch.getEventId(), touch.getDecoyId(), touch.getSourceIp());
        }
        return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
    }

    private String resolveSourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

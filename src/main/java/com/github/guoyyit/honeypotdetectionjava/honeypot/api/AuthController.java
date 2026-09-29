package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import com.github.guoyyit.honeypotdetectionjava.honeypot.config.HoneypotProperties;
import com.github.guoyyit.honeypotdetectionjava.honeypot.detection.DecoyCredentialDetector;
import com.github.guoyyit.honeypotdetectionjava.honeypot.detection.DecoyEndpointFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demo authentication endpoint showing how decoy credential detection
 * hooks into the normal authentication path.
 */
@RestController
public class AuthController {

    private final DecoyCredentialDetector decoyCredentialDetector;
    private final HoneypotProperties properties;

    public AuthController(DecoyCredentialDetector decoyCredentialDetector,
                          HoneypotProperties properties) {
        this.decoyCredentialDetector = decoyCredentialDetector;
        this.properties = properties;
    }

    @PostMapping("/api/auth/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest body,
                                                     HttpServletRequest request) {
        String source = DecoyEndpointFilter.extractSource(request);
        // Decoy check runs for every attempt, regardless of the auth outcome.
        decoyCredentialDetector.check(body.username(), body.password(), source);

        String expected = properties.getLegitUsers().get(body.username());
        if (expected != null && expected.equals(body.password())) {
            return ResponseEntity.ok(Map.of("authenticated", true));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("authenticated", false));
    }

    public record LoginRequest(String username, String password) {
    }
}

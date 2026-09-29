package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demo business endpoints representing normal traffic and health checks.
 */
@RestController
public class BusinessController {

    @GetMapping("/api/business/ping")
    public Map<String, Object> ping() {
        return Map.of("status", "ok");
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "UP");
    }
}

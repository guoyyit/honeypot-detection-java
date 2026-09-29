package com.github.guoyyit.honeypotdetectionjava.web;

import com.github.guoyyit.honeypotdetectionjava.config.HoneypotProperties;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyResource;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyService;
import com.github.guoyyit.honeypotdetectionjava.decoy.SimulatedResponse;
import com.github.guoyyit.honeypotdetectionjava.decoy.TouchKind;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEventService;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionMatch;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CatchAllDecoyController {

    public static final String TRACE_HEADER = "X-Honeypot-Trace";
    public static final String MONITORING_HEADER = "X-Monitoring-Token";

    private final DecoyService decoyService;
    private final TouchEventService touchEventService;
    private final ExemptionService exemptionService;
    private final HoneypotProperties properties;

    public CatchAllDecoyController(DecoyService decoyService,
                                   TouchEventService touchEventService,
                                   ExemptionService exemptionService,
                                   HoneypotProperties properties) {
        this.decoyService = decoyService;
        this.touchEventService = touchEventService;
        this.exemptionService = exemptionService;
        this.properties = properties;
    }

    @RequestMapping("/**")
    public ResponseEntity<String> handle(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/admin") || path.equals(properties.getHealthPath())
                || path.startsWith("/error") || path.equals("/login")) {
            return ResponseEntity.notFound().build();
        }
        DecoyResource decoy = decoyService.findEnabledEndpointByPath(path);
        if (decoy == null) {
            return ResponseEntity.notFound().build();
        }
        String sourceIp = resolveSourceIp(request);
        String userAgent = request.getHeader(HttpHeaders.USER_AGENT);
        ExemptionMatch match = exemptionService.match(sourceIp, path, userAgent,
                MONITORING_HEADER, request.getHeader(MONITORING_HEADER));
        touchEventService.record(decoy.getId(), TouchKind.ENDPOINT, sourceIp, userAgent, path,
                match.isMatched(), match.getRuleId());
        SimulatedResponse simulation = decoy.getSimulatedResponse();
        String traceMarker = properties.getInternalMarker() + ":" + decoy.getId();
        return ResponseEntity.status(simulation.getStatusCode())
                .header(TRACE_HEADER, traceMarker)
                .contentType(MediaType.parseMediaType(
                        simulation.getContentType() != null ? simulation.getContentType()
                                : MediaType.APPLICATION_JSON_VALUE))
                .body(injectMarker(simulation.getBody(), traceMarker,
                        simulation.getContentType()));
    }

    private String injectMarker(String body, String marker, String contentType) {
        String safeBody = body != null ? body : "";
        if (contentType != null && contentType.contains("html")) {
            return safeBody + "<!-- " + marker + " -->";
        }
        return safeBody + "\n// " + marker;
    }

    private String resolveSourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

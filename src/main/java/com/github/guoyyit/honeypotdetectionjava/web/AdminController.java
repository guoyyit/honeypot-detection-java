package com.github.guoyyit.honeypotdetectionjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.alert.Alert;
import com.github.guoyyit.honeypotdetectionjava.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.audit.AuditService;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyResource;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyService;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEventService;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionRule;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final ManagementAuthService authService;
    private final DecoyService decoyService;
    private final ExemptionService exemptionService;
    private final TouchEventService touchEventService;
    private final AlertService alertService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public AdminController(ManagementAuthService authService, DecoyService decoyService,
                           ExemptionService exemptionService, TouchEventService touchEventService,
                           AlertService alertService, AuditService auditService,
                           ObjectMapper objectMapper) {
        this.authService = authService;
        this.decoyService = decoyService;
        this.exemptionService = exemptionService;
        this.touchEventService = touchEventService;
        this.alertService = alertService;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    private String requireActor(HttpServletRequest request) {
        String actor = authService.authenticate(
                request.getHeader(ManagementAuthService.TOKEN_HEADER),
                request.getHeader(ManagementAuthService.ACTOR_HEADER));
        if (actor == null) {
            throw new AdminUnauthorizedException();
        }
        return actor;
    }

    public static class AdminUnauthorizedException extends RuntimeException {
    }

    @PostMapping("/decoys")
    public ResponseEntity<?> createDecoy(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        String actor = requireActor(request);
        DecoyResource input = objectMapper.convertValue(body, DecoyResource.class);
        return ResponseEntity.ok(decoyService.create(input, actor));
    }

    @PostMapping("/decoys/{id}/enable")
    public ResponseEntity<?> enableDecoy(@PathVariable String id, HttpServletRequest request) {
        String actor = requireActor(request);
        return ResponseEntity.ok(decoyService.enable(id, actor));
    }

    @PostMapping("/decoys/{id}/disable")
    public ResponseEntity<?> disableDecoy(@PathVariable String id, HttpServletRequest request) {
        String actor = requireActor(request);
        return ResponseEntity.ok(decoyService.disable(id, actor));
    }

    @org.springframework.web.bind.annotation.DeleteMapping("/decoys/{id}")
    public ResponseEntity<?> deleteDecoy(@PathVariable String id, HttpServletRequest request) {
        String actor = requireActor(request);
        decoyService.delete(id, actor);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/decoys")
    public ResponseEntity<?> listDecoys(HttpServletRequest request) {
        requireActor(request);
        return ResponseEntity.ok(decoyService.list());
    }

    @PostMapping("/exemptions")
    public ResponseEntity<?> createExemption(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        String actor = requireActor(request);
        ExemptionRule input = objectMapper.convertValue(body, ExemptionRule.class);
        return ResponseEntity.ok(exemptionService.create(input, actor));
    }

    @org.springframework.web.bind.annotation.PutMapping("/exemptions/{id}")
    public ResponseEntity<?> updateExemption(@PathVariable String id, @RequestBody Map<String, Object> body,
                                             HttpServletRequest request) {
        String actor = requireActor(request);
        ExemptionRule input = objectMapper.convertValue(body, ExemptionRule.class);
        return ResponseEntity.ok(exemptionService.update(id, input, actor));
    }

    @org.springframework.web.bind.annotation.DeleteMapping("/exemptions/{id}")
    public ResponseEntity<?> deleteExemption(@PathVariable String id, HttpServletRequest request) {
        String actor = requireActor(request);
        exemptionService.delete(id, actor);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/exemptions")
    public ResponseEntity<?> listExemptions(HttpServletRequest request) {
        requireActor(request);
        return ResponseEntity.ok(exemptionService.list());
    }

    @GetMapping("/events")
    public ResponseEntity<?> listEvents(HttpServletRequest request) {
        requireActor(request);
        String decoyId = request.getParameter("decoyId");
        return ResponseEntity.ok(decoyId != null
                ? touchEventService.listByDecoy(decoyId)
                : touchEventService.listAll());
    }

    @GetMapping("/alerts")
    public ResponseEntity<?> listAlerts(HttpServletRequest request) {
        requireActor(request);
        return ResponseEntity.ok(alertService.list());
    }

    @PostMapping("/alerts/{id}/acknowledge")
    public ResponseEntity<?> acknowledgeAlert(@PathVariable String id, HttpServletRequest request) {
        String actor = requireActor(request);
        return ResponseEntity.ok(alertService.acknowledge(id, actor));
    }

    @PostMapping("/alerts/{id}/close")
    public ResponseEntity<?> closeAlert(@PathVariable String id, HttpServletRequest request) {
        String actor = requireActor(request);
        return ResponseEntity.ok(alertService.close(id, actor));
    }

    @GetMapping("/audits")
    public ResponseEntity<?> listAudits(HttpServletRequest request) {
        requireActor(request);
        return ResponseEntity.ok(auditService.list());
    }
}

package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AuditLog;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Management API for listing, acknowledging and closing alerts.
 */
@RestController
@RequestMapping("/api/honeypot/alerts")
public class AlertAdminController {

    private final AlertService alertService;
    private final AuditLog auditLog;

    public AlertAdminController(AlertService alertService, AuditLog auditLog) {
        this.alertService = alertService;
        this.auditLog = auditLog;
    }

    @GetMapping
    public List<Alert> listAlerts() {
        return alertService.listAlerts();
    }

    @PostMapping("/{id}/acknowledge")
    public ResponseEntity<Alert> acknowledge(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return alertService.acknowledge(id)
                .map(alert -> {
                    audit(operator, "ACKNOWLEDGE_ALERT", id);
                    return ResponseEntity.ok(alert);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/close")
    public ResponseEntity<Alert> close(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return alertService.close(id)
                .map(alert -> {
                    audit(operator, "CLOSE_ALERT", id);
                    return ResponseEntity.ok(alert);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private void audit(String operator, String action, String alertId) {
        AuditRecord record = new AuditRecord();
        record.id = "audit-" + UUID.randomUUID();
        record.operator = operator;
        record.action = action;
        record.targetType = "alert";
        record.targetId = alertId;
        record.occurredAt = System.currentTimeMillis();
        auditLog.append(record);
    }
}

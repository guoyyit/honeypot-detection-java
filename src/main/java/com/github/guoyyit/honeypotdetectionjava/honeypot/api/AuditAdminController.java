package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AuditLog;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Management API for reading the audit trail.
 */
@RestController
@RequestMapping("/api/honeypot/audit")
public class AuditAdminController {

    private final AuditLog auditLog;

    public AuditAdminController(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    @GetMapping
    public List<AuditRecord> list() {
        return auditLog.listAll();
    }
}

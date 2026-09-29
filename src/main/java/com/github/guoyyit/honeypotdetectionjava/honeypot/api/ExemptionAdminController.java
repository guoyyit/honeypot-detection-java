package com.github.guoyyit.honeypotdetectionjava.honeypot.api;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.ExemptionRule;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AuditLog;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.ExemptionRuleRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Management API for exemption rules. Rule changes are audited.
 */
@RestController
@RequestMapping("/api/honeypot/exemptions")
public class ExemptionAdminController {

    private final ExemptionRuleRepository repository;
    private final AuditLog auditLog;

    public ExemptionAdminController(ExemptionRuleRepository repository, AuditLog auditLog) {
        this.repository = repository;
        this.auditLog = auditLog;
    }

    @GetMapping
    public List<ExemptionRule> list() {
        return repository.listAll();
    }

    @PostMapping
    public ResponseEntity<ExemptionRule> create(
            @RequestBody ExemptionRule rule,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        if (rule.id != null && repository.findById(rule.id).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
        if (rule.id == null || rule.id.isBlank()) {
            rule.id = "exempt-" + UUID.randomUUID();
        }
        long now = System.currentTimeMillis();
        rule.createdAt = now;
        rule.updatedAt = now;
        repository.save(rule);
        audit(operator, "CREATE_EXEMPTION", rule.id, rule.type + "=" + rule.pattern);
        return ResponseEntity.status(HttpStatus.CREATED).body(rule);
    }

    @PutMapping("/{id}")
    public ResponseEntity<ExemptionRule> update(
            @PathVariable String id,
            @RequestBody ExemptionRule update,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        return repository.findById(id)
                .map(existing -> {
                    existing.name = update.name;
                    existing.type = update.type;
                    existing.pattern = update.pattern;
                    existing.enabled = update.enabled;
                    existing.updatedAt = System.currentTimeMillis();
                    repository.save(existing);
                    audit(operator, "UPDATE_EXEMPTION", id, existing.type + "=" + existing.pattern);
                    return ResponseEntity.ok(existing);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @PathVariable String id,
            @RequestHeader(name = "X-Admin-Name", defaultValue = "admin") String operator) {
        boolean removed = repository.delete(id);
        if (removed) {
            audit(operator, "DELETE_EXEMPTION", id, null);
        }
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private void audit(String operator, String action, String ruleId, String detail) {
        AuditRecord record = new AuditRecord();
        record.id = "audit-" + UUID.randomUUID();
        record.operator = operator;
        record.action = action;
        record.targetType = "exemption";
        record.targetId = ruleId;
        record.detail = detail;
        record.occurredAt = System.currentTimeMillis();
        auditLog.append(record);
    }
}

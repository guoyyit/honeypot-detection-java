package com.github.guoyyit.honeypotdetectionjava.exemption;

import com.github.guoyyit.honeypotdetectionjava.audit.AuditService;
import com.github.guoyyit.honeypotdetectionjava.persist.JsonStateStore;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
public class ExemptionService {

    private final JsonStateStore store;
    private final AuditService auditService;

    public ExemptionService(JsonStateStore store, AuditService auditService) {
        this.store = store;
        this.auditService = auditService;
    }

    public ExemptionRule create(ExemptionRule input, String actor) {
        ExemptionRule[] holder = new ExemptionRule[1];
        store.mutate(state -> {
            long now = System.currentTimeMillis();
            input.setId(input.getId() != null ? input.getId() : UUID.randomUUID().toString());
            input.setCreatedAt(now);
            input.setUpdatedAt(now);
            validate(input);
            state.getExemptionRules().add(input);
            holder[0] = input;
        });
        auditService.record(actor, "CREATE_EXEMPTION", "ExemptionRule", holder[0].getId(),
                "name=" + holder[0].getName(), true);
        return holder[0];
    }

    public ExemptionRule update(String id, ExemptionRule input, String actor) {
        ExemptionRule[] holder = new ExemptionRule[1];
        store.mutate(state -> {
            ExemptionRule existing = state.getExemptionRules().stream()
                    .filter(r -> id.equals(r.getId()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Exemption rule not found: " + id));
            existing.setName(input.getName());
            existing.setEnabled(input.isEnabled());
            existing.setSourceCidr(input.getSourceCidr());
            existing.setPathPrefix(input.getPathPrefix());
            existing.setHeaderName(input.getHeaderName());
            existing.setHeaderValue(input.getHeaderValue());
            existing.setUpdatedAt(System.currentTimeMillis());
            validate(existing);
            holder[0] = existing;
        });
        auditService.record(actor, "UPDATE_EXEMPTION", "ExemptionRule", id,
                "name=" + holder[0].getName(), true);
        return holder[0];
    }

    public void delete(String id, String actor) {
        boolean[] removed = {false};
        store.mutate(state ->
                removed[0] = state.getExemptionRules().removeIf(r -> id.equals(r.getId())));
        if (!removed[0]) {
            auditService.record(actor, "DELETE_EXEMPTION", "ExemptionRule", id, "not found", false);
            throw new IllegalArgumentException("Exemption rule not found: " + id);
        }
        auditService.record(actor, "DELETE_EXEMPTION", "ExemptionRule", id, null, true);
    }

    public List<ExemptionRule> list() {
        return store.read(state -> List.copyOf(state.getExemptionRules()));
    }

    public ExemptionMatch match(String sourceIp, String path, String userAgent,
                                String headerName, String headerValue) {
        List<ExemptionRule> rules = list().stream()
                .filter(ExemptionRule::isEnabled)
                .sorted(Comparator.comparing(ExemptionRule::getCreatedAt))
                .toList();
        for (ExemptionRule rule : rules) {
            if (rule.getSourceCidr() != null && !rule.getSourceCidr().isBlank()) {
                if (!CidrMatcher.contains(rule.getSourceCidr().trim(), sourceIp)) {
                    continue;
                }
            }
            if (rule.getPathPrefix() != null && !rule.getPathPrefix().isBlank()) {
                if (path == null || !path.startsWith(rule.getPathPrefix())) {
                    continue;
                }
            }
            if (rule.getHeaderName() != null && !rule.getHeaderName().isBlank()) {
                if (headerName == null || headerValue == null
                        || !rule.getHeaderName().equalsIgnoreCase(headerName)
                        || (rule.getHeaderValue() != null && !rule.getHeaderValue().isBlank()
                                && !rule.getHeaderValue().equals(headerValue))) {
                    continue;
                }
            }
            return new ExemptionMatch(true, rule.getId());
        }
        return ExemptionMatch.none();
    }

    private static void validate(ExemptionRule rule) {
        if (rule.getName() == null || rule.getName().isBlank()) {
            throw new IllegalArgumentException("Exemption rule requires a name");
        }
        if (rule.getSourceCidr() != null && !rule.getSourceCidr().isBlank()) {
            if (!CidrMatcher.isValidCidr(rule.getSourceCidr().trim())) {
                throw new IllegalArgumentException("Invalid CIDR: " + rule.getSourceCidr());
            }
        }
    }
}

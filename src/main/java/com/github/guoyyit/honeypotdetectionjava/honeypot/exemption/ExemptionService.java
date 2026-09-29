package com.github.guoyyit.honeypotdetectionjava.honeypot.exemption;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.ExemptionRule;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.ExemptionRuleRepository;

import java.util.Optional;

/**
 * Matches incoming traffic against configurable exemption rules
 * (health checks, management interface, internal scheduled jobs).
 * Exempted touches are still persisted as evidence; they only skip alerting.
 */
public class ExemptionService {

    private final ExemptionRuleRepository repository;

    public ExemptionService(ExemptionRuleRepository repository) {
        this.repository = repository;
    }

    public Optional<ExemptionRule> match(String sourceIp, String path, String userAgent) {
        return repository.listAll().stream()
                .filter(rule -> rule.enabled)
                .filter(rule -> matches(rule, sourceIp, path, userAgent))
                .findFirst();
    }

    private boolean matches(ExemptionRule rule, String sourceIp, String path, String userAgent) {
        String value = switch (rule.type) {
            case SOURCE_IP_PREFIX -> sourceIp;
            case PATH_PREFIX -> path;
            case USER_AGENT_PREFIX -> userAgent;
        };
        return value != null && rule.pattern != null && value.startsWith(rule.pattern);
    }
}

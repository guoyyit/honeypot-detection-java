package com.github.guoyyit.honeypotdetectionjava.honeypot.service;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyCredential;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyStatus;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AuditLog;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.DecoyRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Lifecycle management for decoys with duplicate checks and audit logging.
 */
public class DecoyManagementService {

    private final DecoyRepository repository;
    private final AuditLog auditLog;
    private final String adminPathPrefix;

    public DecoyManagementService(DecoyRepository repository, AuditLog auditLog, String adminPathPrefix) {
        this.repository = repository;
        this.auditLog = auditLog;
        this.adminPathPrefix = adminPathPrefix;
    }

    public DecoyEndpoint createEndpoint(DecoyEndpoint endpoint, String operator) {
        validateEndpoint(endpoint);
        synchronized (repository) {
            if (endpoint.id != null && repository.findEndpoint(endpoint.id).isPresent()) {
                throw new DuplicateDecoyException("endpoint id already registered: " + endpoint.id);
            }
            boolean pathTaken = repository.listEndpoints().stream()
                    .anyMatch(e -> e.path.equals(endpoint.path));
            if (pathTaken) {
                throw new DuplicateDecoyException("endpoint path already registered: " + endpoint.path);
            }
            if (endpoint.id == null || endpoint.id.isBlank()) {
                endpoint.id = "decoy-ep-" + UUID.randomUUID();
            }
            long now = System.currentTimeMillis();
            endpoint.createdAt = now;
            endpoint.updatedAt = now;
            repository.saveEndpoint(endpoint);
        }
        audit(operator, "CREATE_ENDPOINT", "endpoint", endpoint.id, "path=" + endpoint.path);
        return endpoint;
    }

    public DecoyCredential createCredential(DecoyCredential credential, String operator) {
        if (credential.username == null || credential.username.isBlank()) {
            throw new InvalidDecoyException("credential username must not be blank");
        }
        synchronized (repository) {
            if (credential.id != null && repository.findCredential(credential.id).isPresent()) {
                throw new DuplicateDecoyException("credential id already registered: " + credential.id);
            }
            boolean usernameTaken = repository.listCredentials().stream()
                    .anyMatch(c -> c.username.equals(credential.username));
            if (usernameTaken) {
                throw new DuplicateDecoyException("credential username already registered: "
                        + credential.username);
            }
            if (credential.id == null || credential.id.isBlank()) {
                credential.id = "decoy-cred-" + UUID.randomUUID();
            }
            long now = System.currentTimeMillis();
            credential.createdAt = now;
            credential.updatedAt = now;
            repository.saveCredential(credential);
        }
        audit(operator, "CREATE_CREDENTIAL", "credential", credential.id,
                "username=" + credential.username);
        return credential;
    }

    public Optional<DecoyEndpoint> setEndpointStatus(String id, boolean enabled, String operator) {
        Optional<DecoyEndpoint> found = repository.findEndpoint(id);
        found.ifPresent(endpoint -> {
            endpoint.status = enabled ? DecoyStatus.ENABLED : DecoyStatus.DISABLED;
            endpoint.updatedAt = System.currentTimeMillis();
            repository.saveEndpoint(endpoint);
            audit(operator, enabled ? "ENABLE_ENDPOINT" : "DISABLE_ENDPOINT", "endpoint", id, null);
        });
        return found;
    }

    public Optional<DecoyCredential> setCredentialStatus(String id, boolean enabled, String operator) {
        Optional<DecoyCredential> found = repository.findCredential(id);
        found.ifPresent(credential -> {
            credential.status = enabled ? DecoyStatus.ENABLED : DecoyStatus.DISABLED;
            credential.updatedAt = System.currentTimeMillis();
            repository.saveCredential(credential);
            audit(operator, enabled ? "ENABLE_CREDENTIAL" : "DISABLE_CREDENTIAL", "credential", id, null);
        });
        return found;
    }

    public boolean deleteEndpoint(String id, String operator) {
        boolean removed = repository.deleteEndpoint(id);
        if (removed) {
            audit(operator, "DELETE_ENDPOINT", "endpoint", id, null);
        }
        return removed;
    }

    public boolean deleteCredential(String id, String operator) {
        boolean removed = repository.deleteCredential(id);
        if (removed) {
            audit(operator, "DELETE_CREDENTIAL", "credential", id, null);
        }
        return removed;
    }

    public List<DecoyEndpoint> listEndpoints() {
        return repository.listEndpoints();
    }

    public List<DecoyCredential> listCredentials() {
        return repository.listCredentials();
    }

    private void validateEndpoint(DecoyEndpoint endpoint) {
        if (endpoint.path == null || !endpoint.path.startsWith("/")) {
            throw new InvalidDecoyException("endpoint path must start with '/'");
        }
        if (endpoint.path.startsWith(adminPathPrefix)) {
            throw new InvalidDecoyException("endpoint path must not shadow the management API: "
                    + adminPathPrefix);
        }
        if (endpoint.responseStatus < 100 || endpoint.responseStatus > 599) {
            throw new InvalidDecoyException("invalid response status: " + endpoint.responseStatus);
        }
    }

    private void audit(String operator, String action, String targetType, String targetId, String detail) {
        AuditRecord record = new AuditRecord();
        record.id = "audit-" + UUID.randomUUID();
        record.operator = operator;
        record.action = action;
        record.targetType = targetType;
        record.targetId = targetId;
        record.detail = detail;
        record.occurredAt = System.currentTimeMillis();
        auditLog.append(record);
    }

    public static class DuplicateDecoyException extends RuntimeException {
        public DuplicateDecoyException(String message) {
            super(message);
        }
    }

    public static class InvalidDecoyException extends RuntimeException {
        public InvalidDecoyException(String message) {
            super(message);
        }
    }
}

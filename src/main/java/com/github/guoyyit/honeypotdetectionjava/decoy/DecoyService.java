package com.github.guoyyit.honeypotdetectionjava.decoy;

import com.github.guoyyit.honeypotdetectionjava.audit.AuditService;
import com.github.guoyyit.honeypotdetectionjava.persist.JsonStateStore;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;

@Service
public class DecoyService {

    public static class DuplicateDecoyException extends RuntimeException {
        public DuplicateDecoyException(String message) {
            super(message);
        }
    }

    private final JsonStateStore store;
    private final AuditService auditService;
    private final Map<String, DecoyResource> enabledCredentialsByUsername = new ConcurrentHashMap<>();

    public DecoyService(JsonStateStore store, AuditService auditService) {
        this.store = store;
        this.auditService = auditService;
    }

    @PostConstruct
    public void initCredentialIndex() {
        store.read(state -> {
            state.getDecoys().stream()
                    .filter(d -> d.getType() == DecoyType.CREDENTIAL
                            && d.getStatus() == DecoyStatus.ENABLED
                            && d.getDecoyUsername() != null)
                    .forEach(d -> enabledCredentialsByUsername.put(d.getDecoyUsername(), d));
            return null;
        });
    }

    public DecoyResource create(DecoyResource input, String actor) {
        DecoyResource[] holder = new DecoyResource[1];
        store.mutate(state -> {
            if (input.getId() != null && state.getDecoys().stream()
                    .anyMatch(d -> input.getId().equals(d.getId()))) {
                throw new DuplicateDecoyException("Decoy id already exists: " + input.getId());
            }
            if (input.getType() == DecoyType.HTTP_ENDPOINT) {
                if (input.getPath() == null || input.getPath().isBlank()) {
                    throw new IllegalArgumentException("HTTP_ENDPOINT decoy requires a path");
                }
                String normalized = normalizePath(input.getPath());
                boolean pathTaken = state.getDecoys().stream().anyMatch(d ->
                        d.getType() == DecoyType.HTTP_ENDPOINT
                                && normalized.equals(d.getPath()));
                if (pathTaken) {
                    throw new DuplicateDecoyException("Decoy path already registered: " + normalized);
                }
                input.setPath(normalized);
            }
            if (input.getType() == DecoyType.CREDENTIAL) {
                if (input.getDecoyUsername() == null || input.getDecoyUsername().isBlank()) {
                    throw new IllegalArgumentException("CREDENTIAL decoy requires a username");
                }
                boolean usernameTaken = state.getDecoys().stream().anyMatch(d ->
                        d.getType() == DecoyType.CREDENTIAL
                                && input.getDecoyUsername().equals(d.getDecoyUsername()));
                if (usernameTaken) {
                    throw new DuplicateDecoyException(
                            "Decoy username already registered: " + input.getDecoyUsername());
                }
                if (input.getDecoyPassword() == null || input.getDecoyPassword().isBlank()) {
                    throw new IllegalArgumentException("CREDENTIAL decoy requires a password");
                }
                input.setDecoyPasswordHash(sha256(input.getDecoyPassword()));
                input.setDecoyPassword(null);
            }
            long now = System.currentTimeMillis();
            input.setId(input.getId() != null ? input.getId() : UUID.randomUUID().toString());
            input.setStatus(DecoyStatus.ENABLED);
            input.setCreatedAt(now);
            input.setUpdatedAt(now);
            if (input.getType() == DecoyType.HTTP_ENDPOINT && input.getSimulatedResponse() == null) {
                input.setSimulatedResponse(defaultResponse());
            }
            state.getDecoys().add(input);
            holder[0] = input;
        });
        if (input.getType() == DecoyType.CREDENTIAL
                && input.getStatus() == DecoyStatus.ENABLED
                && input.getDecoyUsername() != null) {
            enabledCredentialsByUsername.put(input.getDecoyUsername(), input);
        }
        auditService.record(actor, "CREATE_DECOY", "DecoyResource", holder[0].getId(),
                "type=" + holder[0].getType() + ", name=" + holder[0].getName(), true);
        return holder[0];
    }

    public DecoyResource enable(String id, String actor) {
        DecoyResource updated = changeStatus(id, DecoyStatus.ENABLED);
        if (updated.getType() == DecoyType.CREDENTIAL && updated.getDecoyUsername() != null) {
            enabledCredentialsByUsername.put(updated.getDecoyUsername(), updated);
        }
        auditService.record(actor, "ENABLE_DECOY", "DecoyResource", id, null, true);
        return updated;
    }

    public DecoyResource disable(String id, String actor) {
        DecoyResource updated = changeStatus(id, DecoyStatus.DISABLED);
        if (updated.getType() == DecoyType.CREDENTIAL && updated.getDecoyUsername() != null) {
            enabledCredentialsByUsername.remove(updated.getDecoyUsername());
        }
        auditService.record(actor, "DISABLE_DECOY", "DecoyResource", id, null, true);
        return updated;
    }

    public void delete(String id, String actor) {
        boolean[] removed = {false};
        DecoyResource[] removedHolder = new DecoyResource[1];
        store.mutate(state -> {
            DecoyResource target = state.getDecoys().stream()
                    .filter(d -> id.equals(d.getId()))
                    .findFirst()
                    .orElse(null);
            if (target != null) {
                removed[0] = state.getDecoys().remove(target);
                removedHolder[0] = target;
            }
        });
        if (!removed[0]) {
            auditService.record(actor, "DELETE_DECOY", "DecoyResource", id, "not found", false);
            throw new IllegalArgumentException("Decoy not found: " + id);
        }
        if (removedHolder[0] != null && removedHolder[0].getType() == DecoyType.CREDENTIAL
                && removedHolder[0].getDecoyUsername() != null) {
            enabledCredentialsByUsername.remove(removedHolder[0].getDecoyUsername());
        }
        auditService.record(actor, "DELETE_DECOY", "DecoyResource", id, null, true);
    }

    public List<DecoyResource> list() {
        return store.read(state -> List.copyOf(state.getDecoys()));
    }

    public DecoyResource get(String id) {
        return store.read(state -> state.getDecoys().stream()
                .filter(d -> id.equals(d.getId()))
                .findFirst()
                .orElse(null));
    }

    public DecoyResource findEnabledEndpointByPath(String path) {
        String normalized = normalizePath(path);
        return store.read(state -> state.getDecoys().stream()
                .filter(d -> d.getType() == DecoyType.HTTP_ENDPOINT
                        && d.getStatus() == DecoyStatus.ENABLED
                        && normalized.equals(d.getPath()))
                .findFirst()
                .orElse(null));
    }

    public DecoyResource findEnabledCredentialByUsername(String username) {
        if (username == null) {
            return null;
        }
        return enabledCredentialsByUsername.get(username);
    }

    public boolean credentialMatches(DecoyResource decoy, String rawPassword) {
        if (decoy == null || rawPassword == null || decoy.getDecoyPasswordHash() == null) {
            return false;
        }
        String hash = sha256(rawPassword);
        return MessageDigest.isEqual(
                decoy.getDecoyPasswordHash().getBytes(StandardCharsets.UTF_8),
                hash.getBytes(StandardCharsets.UTF_8));
    }

    private DecoyResource changeStatus(String id, DecoyStatus status) {
        DecoyResource[] holder = new DecoyResource[1];
        store.mutate(state -> {
            DecoyResource decoy = state.getDecoys().stream()
                    .filter(d -> id.equals(d.getId()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Decoy not found: " + id));
            decoy.setStatus(status);
            decoy.setUpdatedAt(System.currentTimeMillis());
            holder[0] = decoy;
        });
        return holder[0];
    }

    private static String normalizePath(String path) {
        String normalized = path.startsWith("/") ? path : "/" + path;
        while (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static SimulatedResponse defaultResponse() {
        SimulatedResponse response = new SimulatedResponse();
        response.setStatusCode(200);
        response.setContentType("application/json");
        response.setBody("{\"status\":\"ok\"}");
        return response;
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}

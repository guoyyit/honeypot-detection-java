package com.github.guoyyit.honeypotdetectionjava.decoy;

import com.github.guoyyit.honeypotdetectionjava.audit.AuditService;
import com.github.guoyyit.honeypotdetectionjava.persist.JsonStateStore;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
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

    public DecoyService(JsonStateStore store, AuditService auditService) {
        this.store = store;
        this.auditService = auditService;
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
        auditService.record(actor, "CREATE_DECOY", "DecoyResource", holder[0].getId(),
                "type=" + holder[0].getType() + ", name=" + holder[0].getName(), true);
        return holder[0];
    }

    public DecoyResource enable(String id, String actor) {
        DecoyResource updated = changeStatus(id, DecoyStatus.ENABLED);
        auditService.record(actor, "ENABLE_DECOY", "DecoyResource", id, null, true);
        return updated;
    }

    public DecoyResource disable(String id, String actor) {
        DecoyResource updated = changeStatus(id, DecoyStatus.DISABLED);
        auditService.record(actor, "DISABLE_DECOY", "DecoyResource", id, null, true);
        return updated;
    }

    public void delete(String id, String actor) {
        boolean[] removed = {false};
        store.mutate(state ->
                removed[0] = state.getDecoys().removeIf(d -> id.equals(d.getId())));
        if (!removed[0]) {
            auditService.record(actor, "DELETE_DECOY", "DecoyResource", id, "not found", false);
            throw new IllegalArgumentException("Decoy not found: " + id);
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

    public DecoyResource findEnabledCredential(String username, String rawPassword) {
        if (username == null || rawPassword == null) {
            return null;
        }
        String hash = sha256(rawPassword);
        return store.read(state -> state.getDecoys().stream()
                .filter(d -> d.getType() == DecoyType.CREDENTIAL
                        && d.getStatus() == DecoyStatus.ENABLED
                        && username.equals(d.getDecoyUsername()))
                .filter(d -> d.getDecoyPasswordHash() == null
                        || MessageDigest.isEqual(
                                d.getDecoyPasswordHash().getBytes(StandardCharsets.UTF_8),
                                hash.getBytes(StandardCharsets.UTF_8)))
                .findFirst()
                .orElse(null));
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

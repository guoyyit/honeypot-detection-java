package com.github.guoyyit.honeypotdetectionjava.honeypot.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyCredential;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyStatus;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Persistent registry of decoy endpoints and credentials.
 * State is kept in memory and flushed to decoys.json on every mutation.
 */
public class DecoyRepository {

    private final Path file;
    private final ObjectMapper mapper;
    private final Map<String, DecoyEndpoint> endpoints = new LinkedHashMap<>();
    private final Map<String, DecoyCredential> credentials = new LinkedHashMap<>();
    private final Map<String, DecoyCredential> credentialsByUsername = new LinkedHashMap<>();

    public DecoyRepository(Path dataDir, ObjectMapper mapper) {
        this.file = dataDir.resolve("decoys.json");
        this.mapper = mapper;
        load();
    }

    public synchronized List<DecoyEndpoint> listEndpoints() {
        return new ArrayList<>(endpoints.values());
    }

    public synchronized List<DecoyCredential> listCredentials() {
        return new ArrayList<>(credentials.values());
    }

    public synchronized Optional<DecoyEndpoint> findEndpoint(String id) {
        return Optional.ofNullable(endpoints.get(id));
    }

    public synchronized Optional<DecoyCredential> findCredential(String id) {
        return Optional.ofNullable(credentials.get(id));
    }

    public synchronized Optional<DecoyEndpoint> findEndpointByPath(String path) {
        return endpoints.values().stream()
                .filter(e -> e.status == DecoyStatus.ENABLED && e.path.equals(path))
                .findFirst();
    }

    public synchronized Optional<DecoyCredential> findCredentialByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        DecoyCredential credential = credentialsByUsername.get(username);
        if (credential == null || credential.status != DecoyStatus.ENABLED) {
            return Optional.empty();
        }
        return Optional.of(credential);
    }

    public synchronized void saveEndpoint(DecoyEndpoint endpoint) {
        endpoints.put(endpoint.id, endpoint);
        persist();
    }

    public synchronized void saveCredential(DecoyCredential credential) {
        DecoyCredential previous = credentials.get(credential.id);
        if (previous != null) {
            credentialsByUsername.remove(previous.username);
        }
        credentials.put(credential.id, credential);
        credentialsByUsername.put(credential.username, credential);
        persist();
    }

    public synchronized boolean deleteEndpoint(String id) {
        boolean removed = endpoints.remove(id) != null;
        if (removed) {
            persist();
        }
        return removed;
    }

    public synchronized boolean deleteCredential(String id) {
        DecoyCredential removed = credentials.remove(id);
        if (removed != null) {
            credentialsByUsername.remove(removed.username);
            persist();
        }
        return removed != null;
    }

    private void load() {
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            DecoyFile data = mapper.readValue(file.toFile(), DecoyFile.class);
            if (data.endpoints != null) {
                data.endpoints.forEach(e -> endpoints.put(e.id, e));
            }
            if (data.credentials != null) {
                data.credentials.forEach(c -> {
                    credentials.put(c.id, c);
                    credentialsByUsername.put(c.username, c);
                });
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load decoy registry from " + file, e);
        }
    }

    private void persist() {
        try {
            Files.createDirectories(file.getParent());
            DecoyFile data = new DecoyFile();
            data.endpoints = new ArrayList<>(endpoints.values());
            data.credentials = new ArrayList<>(credentials.values());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), data);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to persist decoy registry to " + file, e);
        }
    }

    static class DecoyFile {
        public List<DecoyEndpoint> endpoints;
        public List<DecoyCredential> credentials;
    }
}

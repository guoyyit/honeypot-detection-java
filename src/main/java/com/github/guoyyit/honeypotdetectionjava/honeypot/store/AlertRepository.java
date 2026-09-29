package com.github.guoyyit.honeypotdetectionjava.honeypot.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AlertStatus;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Persistent store for alerts, including their ack/close state.
 */
public class AlertRepository {

    private final Path file;
    private final ObjectMapper mapper;
    private final Map<String, Alert> alerts = new LinkedHashMap<>();

    public AlertRepository(Path dataDir, ObjectMapper mapper) {
        this.file = dataDir.resolve("alerts.json");
        this.mapper = mapper;
        load();
    }

    public synchronized List<Alert> listAll() {
        return new ArrayList<>(alerts.values());
    }

    public synchronized Optional<Alert> findById(String id) {
        return Optional.ofNullable(alerts.get(id));
    }

    public synchronized Optional<Alert> findActiveByDecoyAndSource(String decoyId, String source) {
        return alerts.values().stream()
                .filter(a -> a.status != AlertStatus.CLOSED
                        && a.decoyId.equals(decoyId) && a.source.equals(source))
                .findFirst();
    }

    public synchronized void save(Alert alert) {
        alerts.put(alert.id, alert);
        persist();
    }

    private void load() {
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            Alert[] data = mapper.readValue(file.toFile(), Alert[].class);
            Arrays.stream(data).forEach(a -> alerts.put(a.id, a));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load alerts from " + file, e);
        }
    }

    private void persist() {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), new ArrayList<>(alerts.values()));
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to persist alerts to " + file, e);
        }
    }
}

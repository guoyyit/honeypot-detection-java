package com.github.guoyyit.honeypotdetectionjava.honeypot.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Append-only durable store for touch events. Events are written before processing,
 * and processed ids are tracked separately so restarts never lose or reprocess events.
 */
public class TouchEventStore {

    private final Path eventsFile;
    private final Path processedFile;
    private final ObjectMapper mapper;
    private final Map<String, TouchEvent> eventsById = new LinkedHashMap<>();
    private final Set<String> processedIds = new HashSet<>();

    public TouchEventStore(Path dataDir, ObjectMapper mapper) {
        this.eventsFile = dataDir.resolve("touch-events.jsonl");
        this.processedFile = dataDir.resolve("processed-events.txt");
        this.mapper = mapper;
        loadEvents();
        loadProcessed();
    }

    public synchronized void append(TouchEvent event) {
        try {
            Files.createDirectories(eventsFile.getParent());
            String line = mapper.writeValueAsString(event) + "\n";
            Files.writeString(eventsFile, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to append touch event to " + eventsFile, e);
        }
        eventsById.put(event.id, event);
    }

    public synchronized List<TouchEvent> listAll() {
        return new ArrayList<>(eventsById.values());
    }

    public synchronized List<TouchEvent> listPending() {
        List<TouchEvent> pending = new ArrayList<>();
        for (TouchEvent event : eventsById.values()) {
            if (!processedIds.contains(event.id)) {
                pending.add(event);
            }
        }
        return pending;
    }

    public synchronized Optional<TouchEvent> findById(String eventId) {
        return Optional.ofNullable(eventsById.get(eventId));
    }

    public synchronized boolean isProcessed(String eventId) {
        return processedIds.contains(eventId);
    }

    public synchronized void markProcessed(String eventId) {
        if (!processedIds.add(eventId)) {
            return;
        }
        try {
            Files.createDirectories(processedFile.getParent());
            Files.writeString(processedFile, eventId + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to mark event processed in " + processedFile, e);
        }
    }

    private void loadEvents() {
        if (!Files.isRegularFile(eventsFile)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(eventsFile, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    TouchEvent event = mapper.readValue(line, TouchEvent.class);
                    eventsById.put(event.id, event);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read touch events from " + eventsFile, e);
        }
    }

    private void loadProcessed() {
        if (!Files.isRegularFile(processedFile)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(processedFile, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    processedIds.add(line.trim());
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load processed ids from " + processedFile, e);
        }
    }
}

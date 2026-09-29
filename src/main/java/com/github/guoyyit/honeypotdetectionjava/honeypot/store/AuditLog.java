package com.github.guoyyit.honeypotdetectionjava.honeypot.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * Append-only audit trail for management operations.
 */
public class AuditLog {

    private final Path file;
    private final ObjectMapper mapper;

    public AuditLog(Path dataDir, ObjectMapper mapper) {
        this.file = dataDir.resolve("audit.jsonl");
        this.mapper = mapper;
    }

    public synchronized void append(AuditRecord record) {
        try {
            Files.createDirectories(file.getParent());
            String line = mapper.writeValueAsString(record) + "\n";
            Files.writeString(file, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to append audit record to " + file, e);
        }
    }

    public synchronized List<AuditRecord> listAll() {
        List<AuditRecord> records = new ArrayList<>();
        if (!Files.isRegularFile(file)) {
            return records;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    records.add(mapper.readValue(line, AuditRecord.class));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read audit log from " + file, e);
        }
        return records;
    }
}

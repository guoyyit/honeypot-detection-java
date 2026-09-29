package com.github.guoyyit.honeypotdetectionjava.honeypot.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.ExemptionRule;

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
 * Persistent store for exemption rules.
 */
public class ExemptionRuleRepository {

    private final Path file;
    private final ObjectMapper mapper;
    private final Map<String, ExemptionRule> rules = new LinkedHashMap<>();

    public ExemptionRuleRepository(Path dataDir, ObjectMapper mapper) {
        this.file = dataDir.resolve("exemptions.json");
        this.mapper = mapper;
        load();
    }

    public synchronized List<ExemptionRule> listAll() {
        return new ArrayList<>(rules.values());
    }

    public synchronized Optional<ExemptionRule> findById(String id) {
        return Optional.ofNullable(rules.get(id));
    }

    public synchronized void save(ExemptionRule rule) {
        rules.put(rule.id, rule);
        persist();
    }

    public synchronized boolean delete(String id) {
        boolean removed = rules.remove(id) != null;
        if (removed) {
            persist();
        }
        return removed;
    }

    private void load() {
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            ExemptionRule[] data = mapper.readValue(file.toFile(), ExemptionRule[].class);
            Arrays.stream(data).forEach(r -> rules.put(r.id, r));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load exemption rules from " + file, e);
        }
    }

    private void persist() {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), new ArrayList<>(rules.values()));
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to persist exemption rules to " + file, e);
        }
    }
}

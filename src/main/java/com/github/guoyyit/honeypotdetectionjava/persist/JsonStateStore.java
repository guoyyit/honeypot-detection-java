package com.github.guoyyit.honeypotdetectionjava.persist;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.config.HoneypotProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Function;

@Component
public class JsonStateStore {

    private static final Logger log = LoggerFactory.getLogger(JsonStateStore.class);

    private final HoneypotProperties properties;
    private final ObjectMapper objectMapper;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private PersistentState state;

    public JsonStateStore(HoneypotProperties properties) {
        this.properties = properties;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
    }

    @PostConstruct
    public void init() {
        Path path = Path.of(properties.getStateFile());
        if (Files.exists(path)) {
            try {
                this.state = objectMapper.readValue(path.toFile(), PersistentState.class);
                log.info("Loaded honeypot state from {} (decoys={}, events={}, alerts={})",
                        path, state.getDecoys().size(), state.getTouchEvents().size(),
                        state.getAlerts().size());
            } catch (IOException e) {
                throw new IllegalStateException("Failed to load state file " + path, e);
            }
        } else {
            this.state = new PersistentState();
        }
    }

    public void mutate(Consumer<PersistentState> mutation) {
        lock.writeLock().lock();
        try {
            mutation.accept(state);
            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public <T> T read(Function<PersistentState, T> query) {
        lock.readLock().lock();
        try {
            return query.apply(state);
        } finally {
            lock.readLock().unlock();
        }
    }

    private void persist() {
        Path path = Path.of(properties.getStateFile());
        Path parent = path.toAbsolutePath().getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = Files.createTempFile(parent, "honeypot-state-", ".tmp");
            try (OutputStream out = Files.newOutputStream(tmp)) {
                objectMapper.writerWithDefaultPrettyPrinter().writeValue(out, state);
                out.flush();
            }
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to persist state to " + path, e);
        }
    }
}

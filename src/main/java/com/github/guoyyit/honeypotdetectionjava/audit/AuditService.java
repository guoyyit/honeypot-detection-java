package com.github.guoyyit.honeypotdetectionjava.audit;

import com.github.guoyyit.honeypotdetectionjava.persist.JsonStateStore;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class AuditService {

    private final JsonStateStore store;

    public AuditService(JsonStateStore store) {
        this.store = store;
    }

    public void record(String actor, String action, String targetType, String targetId,
                       String detail, boolean success) {
        AuditEntry entry = new AuditEntry();
        entry.setId(UUID.randomUUID().toString());
        entry.setTimestamp(System.currentTimeMillis());
        entry.setActor(actor);
        entry.setAction(action);
        entry.setTargetType(targetType);
        entry.setTargetId(targetId);
        entry.setDetail(detail);
        entry.setSuccess(success);
        store.mutate(state -> state.getAuditEntries().add(entry));
    }

    public List<AuditEntry> list() {
        return store.read(state -> List.copyOf(state.getAuditEntries()));
    }
}

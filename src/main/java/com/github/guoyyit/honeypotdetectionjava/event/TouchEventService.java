package com.github.guoyyit.honeypotdetectionjava.event;

import com.github.guoyyit.honeypotdetectionjava.decoy.TouchKind;
import com.github.guoyyit.honeypotdetectionjava.persist.JsonStateStore;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class TouchEventService {

    private final JsonStateStore store;
    private final EventProcessor processor;

    public TouchEventService(JsonStateStore store, EventProcessor processor) {
        this.store = store;
        this.processor = processor;
    }

    public TouchEvent record(String decoyId, TouchKind kind, String sourceIp, String userAgent,
                             String requestPath, boolean exempted, String matchedExemptionId,
                             boolean passwordCorrect) {
        TouchEvent event = new TouchEvent();
        event.setEventId(UUID.randomUUID().toString());
        event.setDecoyId(decoyId);
        event.setKind(kind);
        event.setSourceIp(sourceIp);
        event.setUserAgent(userAgent);
        event.setRequestPath(requestPath);
        event.setTimestamp(System.currentTimeMillis());
        event.setExempted(exempted);
        event.setMatchedExemptionId(matchedExemptionId);
        event.setPasswordCorrect(passwordCorrect);
        event.setProcessed(false);
        store.mutate(state -> state.getTouchEvents().add(event));
        processor.submit(event.getEventId());
        return event;
    }

    public TouchEvent record(String decoyId, TouchKind kind, String sourceIp, String userAgent,
                             String requestPath, boolean exempted, String matchedExemptionId) {
        return record(decoyId, kind, sourceIp, userAgent, requestPath, exempted,
                matchedExemptionId, false);
    }

    public List<TouchEvent> findUnprocessed() {
        return store.read(state -> state.getTouchEvents().stream()
                .filter(e -> !e.isProcessed())
                .sorted((a, b) -> Long.compare(a.getTimestamp(), b.getTimestamp()))
                .toList());
    }

    public void markProcessed(String eventId) {
        store.mutate(state -> state.getTouchEvents().stream()
                .filter(e -> eventId.equals(e.getEventId()))
                .findFirst()
                .ifPresent(e -> e.setProcessed(true)));
    }

    public List<TouchEvent> listByDecoy(String decoyId) {
        return store.read(state -> state.getTouchEvents().stream()
                .filter(e -> decoyId.equals(e.getDecoyId()))
                .toList());
    }

    public List<TouchEvent> listAll() {
        return store.read(state -> List.copyOf(state.getTouchEvents()));
    }
}

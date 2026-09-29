package com.github.guoyyit.honeypotdetectionjava.honeypot.alert;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AlertStatus;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AlertRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Turns touch events into alerts with de-duplication (cooldown window),
 * severity levels derived from decoy sensitivity, and persistent ack/close state.
 */
public class AlertService {

    private final AlertRepository repository;
    private final AlertNotifier notifier;
    private final long cooldownMillis;

    public AlertService(AlertRepository repository, AlertNotifier notifier, long cooldownMillis) {
        this.repository = repository;
        this.notifier = notifier;
        this.cooldownMillis = cooldownMillis;
    }

    public void handleTouch(TouchEvent event) {
        if (event.exempted) {
            // Exempted touches are kept in the event store as evidence but never alert.
            return;
        }
        Optional<Alert> existing = repository.findActiveByDecoyAndSource(event.decoyId, event.source);
        if (existing.isPresent()) {
            Alert alert = existing.get();
            boolean withinCooldown = event.occurredAt - alert.lastTouchAt <= cooldownMillis;
            alert.touchCount++;
            alert.lastTouchAt = event.occurredAt;
            alert.updatedAt = System.currentTimeMillis();
            repository.save(alert);
            if (!withinCooldown) {
                notifier.notify(alert, "Decoy " + event.decoyId + " touched again by " + event.source
                        + " (total " + alert.touchCount + " touches)");
            }
            return;
        }
        Alert alert = new Alert();
        alert.id = "alert-" + UUID.randomUUID();
        alert.decoyId = event.decoyId;
        alert.decoyType = event.decoyType;
        alert.source = event.source;
        alert.level = event.sensitivity.toAlertLevel();
        alert.touchCount = 1;
        alert.firstTouchAt = event.occurredAt;
        alert.lastTouchAt = event.occurredAt;
        alert.updatedAt = System.currentTimeMillis();
        repository.save(alert);
        notifier.notify(alert, "Decoy " + event.decoyId + " (" + event.decoyType + ") touched by "
                + event.source + ": " + event.detail);
    }

    public List<Alert> listAlerts() {
        return repository.listAll();
    }

    public Optional<Alert> acknowledge(String alertId) {
        return transition(alertId, AlertStatus.ACKNOWLEDGED);
    }

    public Optional<Alert> close(String alertId) {
        return transition(alertId, AlertStatus.CLOSED);
    }

    private Optional<Alert> transition(String alertId, AlertStatus target) {
        Optional<Alert> found = repository.findById(alertId);
        found.ifPresent(alert -> {
            alert.status = target;
            alert.updatedAt = System.currentTimeMillis();
            repository.save(alert);
        });
        return found;
    }
}

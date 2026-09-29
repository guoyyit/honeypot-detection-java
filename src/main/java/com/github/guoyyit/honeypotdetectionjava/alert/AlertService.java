package com.github.guoyyit.honeypotdetectionjava.alert;

import com.github.guoyyit.honeypotdetectionjava.audit.AuditService;
import com.github.guoyyit.honeypotdetectionjava.config.HoneypotProperties;
import com.github.guoyyit.honeypotdetectionjava.decoy.AlertSeverity;
import com.github.guoyyit.honeypotdetectionjava.decoy.AlertState;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.persist.JsonStateStore;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class AlertService {

    private final JsonStateStore store;
    private final AlertNotifier notifier;
    private final HoneypotProperties properties;
    private final AuditService auditService;

    public AlertService(JsonStateStore store, AlertNotifier notifier,
                        HoneypotProperties properties, AuditService auditService) {
        this.store = store;
        this.notifier = notifier;
        this.properties = properties;
        this.auditService = auditService;
    }

    public void processEvent(TouchEvent event, int decoySensitivity) {
        AlertSeverity severity = severityFor(decoySensitivity);
        boolean[] shouldNotify = {false};
        Alert[] notified = new Alert[1];
        store.mutate(state -> {
            Alert alert = state.getAlerts().stream()
                    .filter(a -> a.getDecoyId().equals(event.getDecoyId())
                            && a.getSourceIp().equals(event.getSourceIp())
                            && a.getState() != AlertState.CLOSED)
                    .findFirst()
                    .orElse(null);
            long now = event.getTimestamp();
            if (alert == null) {
                alert = new Alert();
                alert.setId(UUID.randomUUID().toString());
                alert.setDecoyId(event.getDecoyId());
                alert.setSourceIp(event.getSourceIp());
                alert.setSeverity(severity);
                alert.setState(AlertState.OPEN);
                alert.setFirstEventAt(now);
                alert.setTouchCount(0);
                alert.setLastNotifiedAt(0L);
                state.getAlerts().add(alert);
            }
            if (severity.ordinal() > alert.getSeverity().ordinal()) {
                alert.setSeverity(severity);
            }
            alert.setLastEventAt(now);
            alert.setTouchCount(alert.getTouchCount() + 1);
            alert.setLastEventId(event.getEventId());
            if (now - alert.getLastNotifiedAt() >= properties.getAlertCooldownMillis()) {
                alert.setLastNotifiedAt(now);
                shouldNotify[0] = true;
                notified[0] = alert;
            }
        });
        if (shouldNotify[0]) {
            notifier.notify(notified[0]);
        }
    }

    public Alert acknowledge(String alertId, String actor) {
        return transition(alertId, AlertState.ACKNOWLEDGED, actor, "ACKNOWLEDGE_ALERT");
    }

    public Alert close(String alertId, String actor) {
        return transition(alertId, AlertState.CLOSED, actor, "CLOSE_ALERT");
    }

    public List<Alert> list() {
        return store.read(state -> List.copyOf(state.getAlerts()));
    }

    public Alert get(String alertId) {
        return store.read(state -> state.getAlerts().stream()
                .filter(a -> alertId.equals(a.getId()))
                .findFirst()
                .orElse(null));
    }

    private Alert transition(String alertId, AlertState target, String actor, String action) {
        Alert[] holder = new Alert[1];
        store.mutate(state -> {
            Alert alert = state.getAlerts().stream()
                    .filter(a -> alertId.equals(a.getId()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Alert not found: " + alertId));
            alert.setState(target);
            holder[0] = alert;
        });
        auditService.record(actor, action, "Alert", alertId,
                "state=" + target, true);
        return holder[0];
    }

    static AlertSeverity severityFor(int sensitivity) {
        if (sensitivity >= 2) {
            return AlertSeverity.CRITICAL;
        }
        if (sensitivity == 1) {
            return AlertSeverity.WARNING;
        }
        return AlertSeverity.INFO;
    }
}

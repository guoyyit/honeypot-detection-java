package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertNotifier;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test notifier that records every notification so tests can verify de-duplication.
 */
public class CapturingAlertNotifier implements AlertNotifier {

    public final List<String> notifications = new CopyOnWriteArrayList<>();

    @Override
    public void notify(Alert alert, String message) {
        notifications.add(alert.decoyId + "|" + alert.source + "|" + alert.level + "|" + message);
    }
}

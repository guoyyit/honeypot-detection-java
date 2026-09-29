package com.github.guoyyit.honeypotdetectionjava.honeypot.alert;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;

/**
 * Delivers alert notifications. Called only when a notification is actually due
 * (never for touches suppressed by the cooldown window).
 */
public interface AlertNotifier {
    void notify(Alert alert, String message);
}

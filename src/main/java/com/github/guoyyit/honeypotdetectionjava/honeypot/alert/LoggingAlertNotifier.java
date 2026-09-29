package com.github.guoyyit.honeypotdetectionjava.honeypot.alert;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default notifier that logs alerts. Replace with webhook/SIEM integration in production.
 */
public class LoggingAlertNotifier implements AlertNotifier {

    private static final Logger log = LoggerFactory.getLogger(LoggingAlertNotifier.class);

    @Override
    public void notify(Alert alert, String message) {
        log.warn("[HONEYPOT-ALERT] level={} alertId={} decoy={} source={} touches={} :: {}",
                alert.level, alert.id, alert.decoyId, alert.source, alert.touchCount, message);
    }
}

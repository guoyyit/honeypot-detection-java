package com.github.guoyyit.honeypotdetectionjava.alert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LoggingAlertNotifier implements AlertNotifier {

    private static final Logger log = LoggerFactory.getLogger(LoggingAlertNotifier.class);

    @Override
    public void notify(Alert alert) {
        log.warn("[HONEYPOT_ALERT] id={} severity={} state={} decoyId={} sourceIp={} "
                        + "touchCount={} firstEventAt={} lastEventAt={}",
                alert.getId(), alert.getSeverity(), alert.getState(), alert.getDecoyId(),
                alert.getSourceIp(), alert.getTouchCount(), alert.getFirstEventAt(),
                alert.getLastEventAt());
    }
}

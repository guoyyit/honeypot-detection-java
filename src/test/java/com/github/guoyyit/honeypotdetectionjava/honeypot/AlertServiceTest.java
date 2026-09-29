package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AlertLevel;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AlertStatus;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyType;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Sensitivity;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AlertRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for alert de-duplication (cooldown window), severity levels and
 * persistent ack/close state.
 */
class AlertServiceTest {

    private static final long COOLDOWN = 60_000;

    @TempDir
    Path dataDir;

    private CapturingAlertNotifier notifier;
    private AlertService alertService;

    @BeforeEach
    void setUp() {
        notifier = new CapturingAlertNotifier();
        alertService = new AlertService(new AlertRepository(dataDir, new ObjectMapper()),
                notifier, COOLDOWN);
    }

    @Test
    void repeatedTouchesWithinCooldownUpgradeExistingAlertWithoutNotifying() {
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.HIGH, 1_000));
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.HIGH, 2_000));
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.HIGH, 3_000));

        assertThat(alertService.listAlerts()).hasSize(1);
        Alert alert = alertService.listAlerts().get(0);
        assertThat(alert.touchCount).isEqualTo(3);
        assertThat(alert.lastTouchAt).isEqualTo(3_000);
        assertThat(notifier.notifications).hasSize(1);
    }

    @Test
    void touchAfterCooldownNotifiesAgainOnSameAlert() {
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.LOW, 1_000));
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.LOW, 1_000 + COOLDOWN + 1));

        assertThat(alertService.listAlerts()).hasSize(1);
        assertThat(alertService.listAlerts().get(0).touchCount).isEqualTo(2);
        assertThat(notifier.notifications).hasSize(2);
    }

    @Test
    void differentSourcesProduceSeparateAlerts() {
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.MEDIUM, 1_000));
        alertService.handleTouch(touch("decoy-a", "2.2.2.2", Sensitivity.MEDIUM, 1_100));

        assertThat(alertService.listAlerts()).hasSize(2);
        assertThat(notifier.notifications).hasSize(2);
    }

    @Test
    void sensitivityMapsToAlertLevel() {
        alertService.handleTouch(touch("decoy-low", "1.1.1.1", Sensitivity.LOW, 1_000));
        alertService.handleTouch(touch("decoy-mid", "1.1.1.1", Sensitivity.MEDIUM, 1_000));
        alertService.handleTouch(touch("decoy-high", "1.1.1.1", Sensitivity.HIGH, 1_000));

        assertThat(alertService.listAlerts())
                .extracting(a -> a.level)
                .containsExactlyInAnyOrder(AlertLevel.INFO, AlertLevel.WARNING, AlertLevel.CRITICAL);
    }

    @Test
    void exemptedTouchProducesNoAlert() {
        TouchEvent event = touch("decoy-a", "10.0.0.1", Sensitivity.HIGH, 1_000);
        event.exempted = true;
        event.exemptionRuleId = "rule-1";
        alertService.handleTouch(event);

        assertThat(alertService.listAlerts()).isEmpty();
        assertThat(notifier.notifications).isEmpty();
    }

    @Test
    void ackAndCloseArePersistedAcrossReload() {
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.HIGH, 1_000));
        alertService.handleTouch(touch("decoy-b", "2.2.2.2", Sensitivity.HIGH, 1_000));
        String ackId = alertService.listAlerts().stream()
                .filter(a -> a.decoyId.equals("decoy-a")).findFirst().orElseThrow().id;
        String closeId = alertService.listAlerts().stream()
                .filter(a -> a.decoyId.equals("decoy-b")).findFirst().orElseThrow().id;

        assertThat(alertService.acknowledge(ackId)).isPresent();
        assertThat(alertService.close(closeId)).isPresent();

        // Simulate a restart: a fresh repository on the same directory.
        AlertRepository reloaded = new AlertRepository(dataDir, new ObjectMapper());
        assertThat(reloaded.findById(ackId)).isPresent()
                .get().extracting(a -> a.status).isEqualTo(AlertStatus.ACKNOWLEDGED);
        assertThat(reloaded.findById(closeId)).isPresent()
                .get().extracting(a -> a.status).isEqualTo(AlertStatus.CLOSED);
    }

    @Test
    void closedAlertAllowsNewAlertForSameSource() {
        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.MEDIUM, 1_000));
        String id = alertService.listAlerts().get(0).id;
        alertService.close(id);

        alertService.handleTouch(touch("decoy-a", "1.1.1.1", Sensitivity.MEDIUM, 2_000));

        assertThat(alertService.listAlerts()).hasSize(2);
        assertThat(notifier.notifications).hasSize(2);
    }

    private TouchEvent touch(String decoyId, String source, Sensitivity sensitivity, long occurredAt) {
        TouchEvent event = new TouchEvent();
        event.id = "evt-" + decoyId + "-" + source + "-" + occurredAt;
        event.decoyId = decoyId;
        event.decoyType = DecoyType.ENDPOINT;
        event.sensitivity = sensitivity;
        event.source = source;
        event.occurredAt = occurredAt;
        event.detail = "test touch";
        return event;
    }
}

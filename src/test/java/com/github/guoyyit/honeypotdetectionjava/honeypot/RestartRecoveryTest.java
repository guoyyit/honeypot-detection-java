package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyType;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Sensitivity;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.honeypot.event.TouchEventProcessor;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AlertRepository;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.DecoyRepository;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.TouchEventStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Events persisted before a restart must be recovered and processed exactly once.
 */
class RestartRecoveryTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @TempDir
    Path dataDir;

    @Test
    void unprocessedEventsSurviveRestartAndAreProcessedExactlyOnce() throws Exception {
        // "First process": persist three events, only one gets processed before the crash.
        TouchEventStore firstStore = new TouchEventStore(dataDir, mapper);
        TouchEvent e1 = touch("evt-1", "decoy-a", "1.1.1.1");
        TouchEvent e2 = touch("evt-2", "decoy-a", "2.2.2.2");
        TouchEvent e3 = touch("evt-3", "decoy-b", "3.3.3.3");
        firstStore.append(e1);
        firstStore.append(e2);
        firstStore.append(e3);
        firstStore.markProcessed("evt-1");

        // "Restart": fresh store instance on the same directory.
        TouchEventStore secondStore = new TouchEventStore(dataDir, mapper);
        assertThat(secondStore.listAll()).hasSize(3);
        assertThat(secondStore.listPending())
                .extracting(e -> e.id)
                .containsExactlyInAnyOrder("evt-2", "evt-3");

        CapturingAlertNotifier notifier = new CapturingAlertNotifier();
        AlertService alertService = new AlertService(
                new AlertRepository(dataDir, mapper), notifier, 60_000);
        TouchEventProcessor processor = new TouchEventProcessor(secondStore, alertService);
        processor.start();
        try {
            assertThat(processor.awaitIdle(Duration.ofSeconds(10))).isTrue();
        } finally {
            processor.stop();
        }

        // Recovered events produced alerts; the already-processed evt-1 did not re-alert.
        assertThat(alertService.listAlerts()).hasSize(2);
        assertThat(notifier.notifications).hasSize(2);
        assertThat(secondStore.listPending()).isEmpty();

        // Re-enqueueing an already-processed event is a no-op (idempotent).
        processor.start();
        try {
            processor.enqueue("evt-2");
            assertThat(processor.awaitIdle(Duration.ofSeconds(10))).isTrue();
        } finally {
            processor.stop();
        }
        assertThat(alertService.listAlerts()).hasSize(2);
        assertThat(alertService.listAlerts().stream().mapToInt(a -> a.touchCount).sum()).isEqualTo(2);
        assertThat(notifier.notifications).hasSize(2);
    }

    @Test
    void decoyRegistrySurvivesReload() {
        DecoyRepository first = new DecoyRepository(dataDir, mapper);
        DecoyEndpoint endpoint = new DecoyEndpoint();
        endpoint.id = "decoy-ep-x";
        endpoint.path = "/x";
        first.saveEndpoint(endpoint);

        DecoyRepository second = new DecoyRepository(dataDir, mapper);
        assertThat(second.findEndpointByPath("/x")).isPresent();
        assertThat(second.findEndpoint("decoy-ep-x")).isPresent();
    }

    private TouchEvent touch(String id, String decoyId, String source) {
        TouchEvent event = new TouchEvent();
        event.id = id;
        event.decoyId = decoyId;
        event.decoyType = DecoyType.ENDPOINT;
        event.sensitivity = Sensitivity.MEDIUM;
        event.source = source;
        event.occurredAt = System.currentTimeMillis();
        event.detail = "test";
        return event;
    }
}

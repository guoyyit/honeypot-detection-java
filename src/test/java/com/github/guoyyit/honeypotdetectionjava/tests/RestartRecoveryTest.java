package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestartRecoveryTest {

    @TempDir
    Path tempDir;

    @Test
    void unprocessedEventsSurviveRestartAndNeverAlertTwice() throws Exception {
        Path stateFile = tempDir.resolve("state.json");
        try (ApplicationProcess first = new ApplicationProcess(stateFile, SocketPorts.freePort())) {
            first.startAndWaitReady();
            first.createEndpointDecoy("restart-decoy-1", "/restart-target", 1);
            first.touch("/restart-target", 20);
            first.waitForEventCount(20, 10000);
            assertEquals(1, first.notificationCount(),
                    "20 rapid touches from one source within cooldown notify exactly once");
        }

        try (ApplicationProcess second = new ApplicationProcess(stateFile, SocketPorts.freePort())) {
            second.startAndWaitReady();
            long deadline = System.currentTimeMillis() + 10000;
            while (System.currentTimeMillis() < deadline) {
                if (second.unprocessedEventCount() == 0) {
                    break;
                }
                Thread.sleep(200);
            }
            assertEquals(0, second.unprocessedEventCount(),
                    "recovered unprocessed events must be processed after restart");
            assertEquals(0, second.notificationCount(),
                    "already-processed events must not re-notify after restart");

            String events = second.getEvents("restart-decoy-1");
            assertEquals(20, events.split("eventId").length - 1);
            assertFalse(events.contains("\"processed\":false"));
        }
    }

    @Test
    void decoysAndAlertsSurviveRestart() throws Exception {
        Path stateFile = tempDir.resolve("state2.json");
        try (ApplicationProcess app = new ApplicationProcess(stateFile, SocketPorts.freePort())) {
            app.startAndWaitReady();
            app.createEndpointDecoy("restart-decoy-2", "/restart-target-2", 2);
            app.touch("/restart-target-2", 1);
            app.waitForEventCount(1, 10000);
        }
        try (ApplicationProcess app2 = new ApplicationProcess(stateFile, SocketPorts.freePort())) {
            app2.startAndWaitReady();
            String decoys = app2.listDecoys();
            assertTrue(decoys.contains("restart-decoy-2"));
            String alerts = app2.listAlerts();
            assertTrue(alerts.contains("restart-decoy-2"));
            assertTrue(alerts.contains("CRITICAL"));
        }
    }
}

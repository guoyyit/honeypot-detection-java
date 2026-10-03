package com.github.guoyyit.honeypotdetectionjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CredentialDetectionTest extends AbstractIntegrationTest {

    private static final String CRED_DECOY_ID = "cred-decoy-1";
    private static final String DECOY_USERNAME = "backup-admin";
    private static final String DECOY_PASSWORD = "S3cret-decoy!";

    @BeforeAll
    void setUp() {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", CRED_DECOY_ID,
                "name", "decoy db account",
                "type", "CREDENTIAL",
                "sensitivity", 2,
                "decoyUsername", DECOY_USERNAME,
                "decoyPassword", DECOY_PASSWORD), String.class);
    }

    @Test
    void decoyUsernameWithCorrectPasswordRecordsDistinguishableEvent() throws Exception {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "cred-correct-only",
                "name", "correct password only",
                "type", "CREDENTIAL",
                "sensitivity", 2,
                "decoyUsername", "correct-only-user",
                "decoyPassword", "correct-only-pw"), String.class);

        int status = loginWithForwardedIp("correct-only-user", "correct-only-pw",
                "203.0.117.10");
        assertEquals(401, status, "login with decoy credentials must still fail");

        JsonNode currentEvent = waitForCredentialEvent("cred-correct-only", true);
        assertEquals("cred-correct-only", currentEvent.path("decoyId").asText());
        assertEquals("CREDENTIAL", currentEvent.path("kind").asText());
        assertFalse(currentEvent.path("sourceIp").asText().isBlank());

        String alerts = waitForAlertContaining("cred-correct-only");
        assertTrue(alerts.contains("CRITICAL"));
    }

    @Test
    void decoyUsernameWithWrongPasswordAlsoRecordsEventAndIsDistinguishable() throws Exception {
        int status = loginWithForwardedIp(DECOY_USERNAME, "totally-wrong-password",
                "203.0.117.11");
        assertEquals(401, status, "login must keep failing with a wrong password");

        JsonNode wrongEvent = waitForCredentialEvent(CRED_DECOY_ID, false);
        assertFalse(wrongEvent.path("passwordMatched").asBoolean(true),
                "the wrong-password event must be marked as a non-matching password");
        assertTrue(allEventsContainMatchFlag(true),
                "a correct-password event from another login must remain distinguishable");

        String alerts = waitForAlertContaining(CRED_DECOY_ID);
        assertTrue(alerts.contains("203.0.117.11"),
                "wrong-password guesses enter the alert chain under their own source key");
    }

    @Test
    void normalCredentialsNeverProduceTouchEvents() throws Exception {
        long before = countEvents();
        assertEquals(401, login("normal-user", "whatever"));
        assertEquals(401, login("another-normal-user", "hunter2"));
        Thread.sleep(600);
        assertEquals(before, countEvents(),
                "normal credentials must not create any touch events");
    }

    @Test
    void disabledAndDeletedDecoyCredentialsStopProducingEvents() throws Exception {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "cred-decoy-disable",
                "name", "to disable",
                "type", "CREDENTIAL",
                "sensitivity", 1,
                "decoyUsername", "disable-me",
                "decoyPassword", "pw-disable"), String.class);
        adminExchange("/admin/decoys/cred-decoy-disable/disable",
                HttpMethod.POST, null, String.class);

        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "cred-decoy-delete",
                "name", "to delete",
                "type", "CREDENTIAL",
                "sensitivity", 1,
                "decoyUsername", "delete-me",
                "decoyPassword", "pw-delete"), String.class);
        adminExchange("/admin/decoys/cred-decoy-delete",
                HttpMethod.DELETE, null, Void.class);

        long before = adminExchange("/admin/events", HttpMethod.GET, null, String.class)
                .getBody().split("eventId").length - 1L;
        assertEquals(401, login("disable-me", "pw-disable"));
        assertEquals(401, login("disable-me", "wrong"));
        assertEquals(401, login("delete-me", "pw-delete"));
        assertEquals(401, login("delete-me", "wrong"));
        Thread.sleep(600);

        String allEvents = adminExchange("/admin/events", HttpMethod.GET, null, String.class)
                .getBody();
        assertFalse(allEvents.contains("cred-decoy-disable"));
        assertFalse(allEvents.contains("cred-decoy-delete"));
        assertEquals(before, allEvents.split("eventId").length - 1L,
                "disabled/deleted decoy usernames must not produce events");
    }

    @Test
    void normalLoginOverheadDoesNotGrowWithRegisteredDecoyCount() throws Exception {
        int decoyCount = 500;
        for (int i = 0; i < decoyCount; i++) {
            adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                    "id", "bulk-cred-" + i,
                    "name", "bulk decoy",
                    "type", "CREDENTIAL",
                    "sensitivity", 0,
                    "decoyUsername", "decoy-bulk-user-" + i,
                    "decoyPassword", "bulk-pw-" + i), String.class);
        }

        // Warm up the HTTP path and the lazy credential index.
        for (int i = 0; i < 20; i++) {
            login("warmup-normal-user", "warmup-pw");
        }

        int iterations = 200;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            login("legit-user-" + i, "legit-password");
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        long averageMicros = elapsedMillis * 1000L / iterations;

        assertTrue(averageMicros < 20_000,
                "normal login must stay cheap with " + decoyCount
                        + " registered decoys, was " + averageMicros + "us/request");

        Thread.sleep(500);
        String allEvents = adminExchange("/admin/events", HttpMethod.GET, null, String.class)
                .getBody();
        assertFalse(allEvents.contains("legit-user-0"));
    }

    private String eventsForDecoy() {
        return eventsOf(CRED_DECOY_ID);
    }

    private String eventsOf(String decoyId) {
        return adminExchange("/admin/events?decoyId=" + decoyId,
                HttpMethod.GET, null, String.class).getBody();
    }

    private JsonNode waitForCredentialEvent(String decoyId, boolean passwordMatched)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            try {
                JsonNode array = new ObjectMapper().readTree(eventsOf(decoyId));
                for (int i = array.size() - 1; i >= 0; i--) {
                    JsonNode event = array.get(i);
                    if ("CREDENTIAL".equals(event.path("kind").asText())
                            && event.path("passwordMatched").asBoolean(!passwordMatched)
                                    == passwordMatched) {
                        return event;
                    }
                }
            } catch (Exception ignored) {
                // Retry until the deadline.
            }
            Thread.sleep(100);
        }
        throw new AssertionError(
                "no credential event with passwordMatched=" + passwordMatched + " for " + decoyId);
    }

    private String waitForAlertContaining(String decoyId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class)
                    .getBody();
            if (alerts.contains("\"decoyId\":\"" + decoyId + "\"")) {
                return alerts;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("no alert created for decoy " + decoyId);
    }

    private boolean allEventsContainMatchFlag(boolean flag) throws Exception {
        JsonNode array = new ObjectMapper().readTree(
                adminExchange("/admin/events", HttpMethod.GET, null, String.class).getBody());
        for (JsonNode event : array) {
            if ("CREDENTIAL".equals(event.path("kind").asText())
                    && event.path("passwordMatched").asBoolean() == flag) {
                return true;
            }
        }
        return false;
    }

    private long countEvents() {
        return eventsForDecoy().split("eventId").length - 1L;
    }

    private int login(String username, String password) {
        return loginWithForwardedIp(username, password, null);
    }

    private int loginWithForwardedIp(String username, String password, String forwardedIp) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (forwardedIp != null) {
            headers.set("X-Forwarded-For", forwardedIp);
        }
        HttpEntity<Map<String, String>> entity = new HttpEntity<>(
                Map.of("username", username, "password", password), headers);
        ResponseEntity<String> response = rest.exchange(url("/login"),
                HttpMethod.POST, entity, String.class);
        return response.getStatusCode().value();
    }
}

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
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CredentialDetectionTest extends AbstractIntegrationTest {

    private static final String CRED_DECOY_ID = "cred-decoy-1";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    void setUp() {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", CRED_DECOY_ID,
                "name", "decoy db account",
                "type", "CREDENTIAL",
                "sensitivity", 2,
                "decoyUsername", "backup-admin",
                "decoyPassword", "S3cret-decoy!"), String.class);
    }

    @Test
    void correctPasswordRecordsTouchEventMarkedAsCorrect() throws Exception {
        int status = login("backup-admin", "S3cret-decoy!");
        assertEquals(401, status, "login must still fail");

        waitForEventWithPasswordCorrect(true);

        String events = adminExchange("/admin/events?decoyId=" + CRED_DECOY_ID,
                HttpMethod.GET, null, String.class).getBody();
        assertTrue(events.contains("\"decoyId\":\"" + CRED_DECOY_ID + "\""));
        assertTrue(events.contains("CREDENTIAL"));
        assertTrue(events.contains("\"sourceIp\""));
        assertTrue(hasEventWithPasswordCorrect(events, true),
                "correct password event must be marked passwordCorrect=true");

        String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        assertTrue(alerts.contains(CRED_DECOY_ID));
        assertTrue(alerts.contains("CRITICAL"));
    }

    @Test
    void wrongPasswordOnDecoyUsernameRecordsTouchEventMarkedAsIncorrect() throws Exception {
        long before = countEvents();
        int status = login("backup-admin", "totally-wrong-password");
        assertEquals(401, status, "decoy credential login still fails regardless of password");

        waitForEventWithPasswordCorrect(false);

        long after = countEvents();
        assertTrue(after > before,
                "wrong password with a registered decoy username must create a touch event");

        String events = adminExchange("/admin/events?decoyId=" + CRED_DECOY_ID,
                HttpMethod.GET, null, String.class).getBody();
        assertTrue(hasEventWithPasswordCorrect(events, false),
                "wrong password event must be marked passwordCorrect=false");
    }

    @Test
    void normalCredentialsNeverCreateTouchEvent() throws InterruptedException {
        long before = countEvents();
        login("normal-user", "whatever");
        login("another-user", "another-password");
        Thread.sleep(500);
        assertEquals(before, countEvents(), "normal credentials must not create events");
    }

    private boolean hasEventWithPasswordCorrect(String eventsBody, boolean expected) throws Exception {
        JsonNode array = objectMapper.readTree(eventsBody);
        for (JsonNode event : array) {
            if (CRED_DECOY_ID.equals(event.get("decoyId").asText())
                    && event.has("passwordCorrect")
                    && event.get("passwordCorrect").asBoolean() == expected) {
                return true;
            }
        }
        return false;
    }

    private void waitForEventWithPasswordCorrect(boolean expected) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            String events = adminExchange("/admin/events?decoyId=" + CRED_DECOY_ID,
                    HttpMethod.GET, null, String.class).getBody();
            if (events.contains("\"passwordCorrect\":" + expected)
                    && !events.contains("\"processed\":false")) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("event with passwordCorrect=" + expected + " not recorded in time");
    }

    private long countEvents() {
        String events = adminExchange("/admin/events?decoyId=" + CRED_DECOY_ID,
                HttpMethod.GET, null, String.class).getBody();
        return events.split("eventId").length - 1L;
    }

    private int login(String username, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, String>> entity = new HttpEntity<>(
                Map.of("username", username, "password", password), headers);
        ResponseEntity<String> response = rest.exchange(url("/login"),
                HttpMethod.POST, entity, String.class);
        return response.getStatusCode().value();
    }
}

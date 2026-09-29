package com.github.guoyyit.honeypotdetectionjava.tests;

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
    void decoyCredentialLoginRecordsTouchEventRegardlessOfAuthResult() throws Exception {
        int status = login("backup-admin", "S3cret-decoy!");
        assertEquals(401, status, "login must still fail");

        long deadline = System.currentTimeMillis() + 8000;
        String events;
        do {
            events = adminExchange("/admin/events?decoyId=" + CRED_DECOY_ID,
                    HttpMethod.GET, null, String.class).getBody();
            if (events.contains("eventId") && !events.contains("\"processed\":false")) {
                break;
            }
            Thread.sleep(100);
        } while (System.currentTimeMillis() < deadline);

        assertTrue(events.contains("\"decoyId\":\"" + CRED_DECOY_ID + "\""));
        assertTrue(events.contains("CREDENTIAL"));
        assertTrue(events.contains("\"sourceIp\""));
        String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        assertTrue(alerts.contains(CRED_DECOY_ID));
        assertTrue(alerts.contains("CRITICAL"));
    }

    @Test
    void wrongPasswordDoesNotMatchDecoy() throws InterruptedException {
        long before = countEvents();
        login("backup-admin", "totally-wrong-password");
        login("normal-user", "whatever");
        Thread.sleep(500);
        assertEquals(before, countEvents(), "non-matching credentials must not create events");
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

package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DecoyLifecycleTest extends AbstractIntegrationTest {

    private String decoyId;

    @BeforeAll
    void setUp() {
        Map<String, Object> decoy = Map.of(
                "id", "life-endpoint-1",
                "name", "fake admin panel",
                "type", "HTTP_ENDPOINT",
                "sensitivity", 2,
                "path", "/fake-admin",
                "simulatedResponse", Map.of(
                        "statusCode", 200,
                        "contentType", "text/html",
                        "body", "<html>login</html>"));
        ResponseEntity<String> created = adminExchange("/admin/decoys",
                HttpMethod.POST, decoy, String.class);
        assertEquals(HttpStatus.OK, created.getStatusCode());

        ResponseEntity<String> duplicate = adminExchange("/admin/decoys",
                HttpMethod.POST, decoy, String.class);
        assertEquals(HttpStatus.CONFLICT, duplicate.getStatusCode());

        Map<String, Object> samePath = Map.of(
                "name", "dup path",
                "type", "HTTP_ENDPOINT",
                "sensitivity", 1,
                "path", "/fake-admin");
        ResponseEntity<String> pathDup = adminExchange("/admin/decoys",
                HttpMethod.POST, samePath, String.class);
        assertEquals(HttpStatus.CONFLICT, pathDup.getStatusCode());

        decoyId = "life-endpoint-1";
    }

    @Test
    void enabledDecoyProducesSimulationAndTouchEvent() throws Exception {
        ResponseEntity<String> response = rest.getForEntity(url("/fake-admin"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("login"));
        String marker = response.getHeaders().getFirst("X-Honeypot-Trace");
        assertNotNull(marker);
        assertTrue(marker.contains(decoyId));

        waitForProcessed(1);

        ResponseEntity<String> events = adminExchange("/admin/events?decoyId=" + decoyId,
                HttpMethod.GET, null, String.class);
        assertTrue(events.getBody().contains(decoyId));

        ResponseEntity<String> alerts = adminExchange("/admin/alerts",
                HttpMethod.GET, null, String.class);
        assertTrue(alerts.getBody().contains("\"decoyId\":\"" + decoyId + "\""));
    }

    @Test
    void disabledDecoyStopsProducingAlerts() throws Exception {
        ResponseEntity<String> disabled = adminExchange("/admin/decoys/" + decoyId + "/disable",
                HttpMethod.POST, null, String.class);
        assertEquals(HttpStatus.OK, disabled.getStatusCode());

        ResponseEntity<String> response = rest.getForEntity(url("/fake-admin"), String.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());

        long eventsBefore = countEvents(decoyId);
        Thread.sleep(300);
        assertEquals(eventsBefore, countEvents(decoyId));

        adminExchange("/admin/decoys/" + decoyId + "/enable", HttpMethod.POST, null, String.class);
    }

    @Test
    void deletedDecoyStopsProducingAlerts() {
        Map<String, Object> decoy = Map.of(
                "id", "life-endpoint-del",
                "name", "to delete",
                "type", "HTTP_ENDPOINT",
                "sensitivity", 1,
                "path", "/fake-delete");
        adminExchange("/admin/decoys", HttpMethod.POST, decoy, String.class);

        ResponseEntity<Void> deleted = adminExchange("/admin/decoys/life-endpoint-del",
                HttpMethod.DELETE, null, Void.class);
        assertEquals(HttpStatus.NO_CONTENT, deleted.getStatusCode());

        ResponseEntity<String> response = rest.getForEntity(url("/fake-delete"), String.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());

        ResponseEntity<String> deleteAgain = adminExchange("/admin/decoys/life-endpoint-del",
                HttpMethod.DELETE, null, String.class);
        assertEquals(HttpStatus.NOT_FOUND, deleteAgain.getStatusCode());
    }

    @Test
    void adminApiRequiresToken() {
        ResponseEntity<String> response = rest.getForEntity(url("/admin/decoys"), String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    private long countEvents(String decoyId) {
        ResponseEntity<String> events = adminExchange("/admin/events?decoyId=" + decoyId,
                HttpMethod.GET, null, String.class);
        return events.getBody().split("eventId").length - 1L;
    }

    private void waitForProcessed(long expectedAtLeast) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline) {
            if (countEvents(decoyId) >= expectedAtLeast
                    && alertsContain(decoyId)) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("touch event was not processed in time");
    }

    private boolean alertsContain(String decoyId) {
        ResponseEntity<String> alerts = adminExchange("/admin/alerts",
                HttpMethod.GET, null, String.class);
        return alerts.getBody().contains("\"decoyId\":\"" + decoyId + "\"");
    }
}

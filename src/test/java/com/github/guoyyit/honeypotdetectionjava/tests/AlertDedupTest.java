package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AlertDedupTest extends AbstractIntegrationTest {

    @BeforeAll
    void setUp() {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "dedup-low", "name", "low", "type", "HTTP_ENDPOINT",
                "sensitivity", 0, "path", "/dedup-low"), String.class);
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "dedup-critical", "name", "critical", "type", "HTTP_ENDPOINT",
                "sensitivity", 2, "path", "/dedup-critical"), String.class);
    }

    @Test
    void repeatedTouchesWithinCooldownShareSingleAlertAndEscalateCount() throws Exception {
        for (int i = 0; i < 5; i++) {
            rest.getForEntity(url("/dedup-low"), String.class);
        }
        waitUntil(() -> countAlerts("dedup-low") == 1 && touchCount("dedup-low") == 5);

        String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        int idx = alerts.indexOf("\"decoyId\":\"dedup-low\"");
        String segment = alerts.substring(Math.max(0, idx - 200), Math.min(alerts.length(), idx + 400));
        assertTrue(segment.contains("\"touchCount\":5"));
        assertTrue(segment.contains("INFO"));
    }

    @Test
    void sensitivityMapsToSeverity() throws Exception {
        rest.getForEntity(url("/dedup-critical"), String.class);
        waitUntil(() -> countAlerts("dedup-critical") == 1);
        String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        int idx = alerts.indexOf("\"decoyId\":\"dedup-critical\"");
        String segment = alerts.substring(Math.max(0, idx - 200), Math.min(alerts.length(), idx + 400));
        assertTrue(segment.contains("CRITICAL"));
    }

    @Test
    void differentSourcesCreateDifferentAlertsAndAckClosePersist() throws Exception {
        rest.getForEntity(url("/dedup-low"), String.class);

        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.set("X-Forwarded-For", "10.9.9.9");
        rest.exchange(url("/dedup-low"), HttpMethod.GET,
                new org.springframework.http.HttpEntity<>(headers), String.class);

        waitUntil(() -> distinctSourcesFor("dedup-low") >= 2);
        String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();

        String alertId = findOpenAlertId("dedup-low", "10.9.9.9");
        ResponseEntity<String> ack = adminExchange("/admin/alerts/" + alertId + "/acknowledge",
                HttpMethod.POST, null, String.class);
        assertEquals(HttpStatus.OK, ack.getStatusCode());
        assertTrue(ack.getBody().contains("ACKNOWLEDGED"));

        ResponseEntity<String> close = adminExchange("/admin/alerts/" + alertId + "/close",
                HttpMethod.POST, null, String.class);
        assertTrue(close.getBody().contains("CLOSED"));

        String audits = adminExchange("/admin/audits", HttpMethod.GET, null, String.class).getBody();
        assertTrue(audits.contains("ACKNOWLEDGE_ALERT"));
        assertTrue(audits.contains("CLOSE_ALERT"));
    }

    private long countAlerts(String decoyId) {
        return occurrences(adminExchange("/admin/alerts", HttpMethod.GET, null, String.class)
                .getBody(), "\"decoyId\":\"" + decoyId + "\"");
    }

    private long distinctSourcesFor(String decoyId) {
        String body = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        long local = occurrences(body, "\"decoyId\":\"" + decoyId + "\",\"sourceIp\":\"127.0.0.1\"");
        long other = occurrences(body, "\"decoyId\":\"" + decoyId + "\",\"sourceIp\":\"10.9.9.9\"");
        return (local > 0 ? 1 : 0) + (other > 0 ? 1 : 0);
    }

    private long touchCount(String decoyId) {
        String body = adminExchange("/admin/events?decoyId=" + decoyId,
                HttpMethod.GET, null, String.class).getBody();
        return occurrences(body, "\"eventId\"");
    }

    private String findOpenAlertId(String decoyId, String sourceIp) {
        String body = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        int pos = body.indexOf("\"decoyId\":\"" + decoyId + "\",\"sourceIp\":\"" + sourceIp + "\"");
        assertTrue(pos > 0, "alert for source not found");
        String prefix = body.substring(0, pos);
        int idPos = prefix.lastIndexOf("\"id\":\"");
        return prefix.substring(idPos + 6, prefix.indexOf("\"", idPos + 6));
    }

    private static long occurrences(String text, String token) {
        long count = 0;
        int pos = 0;
        while ((pos = text.indexOf(token, pos)) >= 0) {
            count++;
            pos += token.length();
        }
        return count;
    }
}

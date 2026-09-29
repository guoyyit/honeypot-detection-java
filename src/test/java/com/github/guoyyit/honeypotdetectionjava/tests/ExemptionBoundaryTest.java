package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ExemptionBoundaryTest extends AbstractIntegrationTest {

    @BeforeAll
    void setUp() {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "exempt-decoy", "name", "exempt target", "type", "HTTP_ENDPOINT",
                "sensitivity", 1, "path", "/exempt-target"), String.class);

        ResponseEntity<String> created = adminExchange("/admin/exemptions", HttpMethod.POST, Map.of(
                "name", "internal monitoring",
                "sourceCidr", "192.168.0.0/16"), String.class);
        assertTrue(created.getStatusCode().is2xxSuccessful());

        ResponseEntity<String> invalid = adminExchange("/admin/exemptions", HttpMethod.POST, Map.of(
                "name", "bad cidr",
                "sourceCidr", "not-a-cidr"), String.class);
        assertEquals(400, invalid.getStatusCode().value());

        ResponseEntity<String> audits = adminExchange("/admin/audits",
                HttpMethod.GET, null, String.class);
        assertTrue(audits.getBody().contains("CREATE_EXEMPTION"));
    }

    @Test
    void healthAndAdminTrafficNeverCreateTouchEvents() throws InterruptedException {
        rest.getForEntity(url("/healthz"), String.class);
        adminExchange("/admin/decoys", HttpMethod.GET, null, String.class);
        Thread.sleep(400);
        String allEvents = adminExchange("/admin/events", HttpMethod.GET, null, String.class).getBody();
        assertFalse(allEvents.contains("/healthz"));
        assertFalse(allEvents.contains("/admin/decoys"));
    }

    @Test
    void exemptedSourceStillRecordsEvidenceButCreatesNoAlert() throws Exception {
        getWithForwardedIp("/exempt-target", "192.168.10.20");
        waitForEventWithExemption(true);

        String events = adminExchange("/admin/events?decoyId=exempt-decoy",
                HttpMethod.GET, null, String.class).getBody();
        assertTrue(events.contains("\"exempted\":true"));
        assertTrue(events.contains("\"matchedExemptionId\""));

        String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        assertFalse(alerts.contains("\"sourceIp\":\"192.168.10.20\""),
                "exempted source must not create an alert");
    }

    @Test
    void nonExemptedSourceCreatesAlertAndEvidenceRemainsAfterRuleDeletion() throws Exception {
        getWithForwardedIp("/exempt-target", "203.0.113.77");
        waitForEventWithExemption(false);

        String events = adminExchange("/admin/events?decoyId=exempt-decoy",
                HttpMethod.GET, null, String.class).getBody();
        assertTrue(events.contains("203.0.113.77"));
        assertTrue(events.contains("\"exempted\":false"));

        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
            if (alerts.contains("\"sourceIp\":\"203.0.113.77\"")) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("attack from non-exempted source should create an alert");
    }

    @Test
    void headerBasedExemptionSuppressesAlertButKeepsEvidence() throws Exception {
        ResponseEntity<String> ruleResponse = adminExchange("/admin/exemptions", HttpMethod.POST, Map.of(
                "name", "monitoring token rule",
                "headerName", "X-Monitoring-Token",
                "headerValue", "probe-secret"), String.class);
        assertEquals(200, ruleResponse.getStatusCode().value());
        String body = ruleResponse.getBody();
        String ruleId = body.substring(body.indexOf("\"id\":\"") + 6,
                body.indexOf("\"", body.indexOf("\"id\":\"") + 6));

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Monitoring-Token", "probe-secret");
        rest.exchange(url("/exempt-target"), HttpMethod.GET,
                new HttpEntity<>(headers), String.class);

        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            String events = adminExchange("/admin/events", HttpMethod.GET, null, String.class).getBody();
            if (events.contains("\"matchedExemptionId\":\"" + ruleId + "\"")) {
                assertTrue(events.contains("\"exempted\":true"));
                String alerts = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class)
                        .getBody();
                assertFalse(alerts.contains("\"matchedExemptionId\""));
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("header-exempted evidence not recorded");
    }

    private void getWithForwardedIp(String path, String ip) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", ip);
        ResponseEntity<String> response = rest.exchange(url(path), HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
        assertEquals(200, response.getStatusCode().value());
    }

    private void waitForEventWithExemption(boolean exempted) throws InterruptedException {
        String token = "\"exempted\":" + exempted;
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            String events = adminExchange("/admin/events?decoyId=exempt-decoy",
                    HttpMethod.GET, null, String.class).getBody();
            if (events.contains(token)) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("exempted event evidence not recorded");
    }
}

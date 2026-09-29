package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "honeypot.admin-token=test-admin-token",
                "honeypot.alert-cooldown-millis=300"
        })
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AlertCooldownTest extends AbstractIntegrationTest {

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.state-file", () -> System.getProperty("java.io.tmpdir")
                + "/honeypot-test-" + java.util.UUID.randomUUID() + "/state.json");
    }

    @BeforeAll
    void setUp() {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "cooldown-decoy", "name", "cooldown", "type", "HTTP_ENDPOINT",
                "sensitivity", 0, "path", "/cooldown-target"), String.class);
    }

    @Test
    void repeatedTouchesCreateRepeatedNotificationsAfterCooldownButStayOnSameAlert()
            throws Exception {
        rest.getForEntity(url("/cooldown-target"), String.class);
        waitUntil(() -> countAlerts() == 1);

        long lastNotifiedBefore = lastNotifiedAt();

        Thread.sleep(500);
        rest.getForEntity(url("/cooldown-target"), String.class);

        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            if (touchCount() == 2 && lastNotifiedAt() > lastNotifiedBefore) {
                break;
            }
            Thread.sleep(100);
        }
        assertEquals(1, countAlerts(), "same source + decoy must keep a single alert");
        assertEquals(2, touchCount());
        assertTrue(lastNotifiedAt() > lastNotifiedBefore,
                "notification timestamp must advance after cooldown");
    }

    private long countAlerts() {
        return occurrences(adminExchange("/admin/alerts", HttpMethod.GET, null, String.class)
                .getBody(), "cooldown-decoy");
    }

    private long touchCount() {
        return occurrences(adminExchange("/admin/events?decoyId=cooldown-decoy",
                HttpMethod.GET, null, String.class).getBody(), "\"eventId\"");
    }

    private long lastNotifiedAt() {
        String body = adminExchange("/admin/alerts", HttpMethod.GET, null, String.class).getBody();
        int idx = body.indexOf("\"lastNotifiedAt\":");
        String raw = body.substring(idx + 17, body.indexOf(",", idx));
        return Long.parseLong(raw);
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

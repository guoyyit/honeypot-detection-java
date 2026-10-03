package com.github.guoyyit.honeypotdetectionjava.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ConcurrentTouchTest extends AbstractIntegrationTest {

    private static final String DECOY_ID = "concurrent-endpoint-1";
    private static final int THREADS = 32;
    private static final int CALLS_PER_THREAD = 10;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    void setUp() {
        Map<String, Object> decoy = Map.of(
                "id", DECOY_ID,
                "name", "concurrent decoy",
                "type", "HTTP_ENDPOINT",
                "sensitivity", 1,
                "path", "/concurrent-target");
        adminExchange("/admin/decoys", HttpMethod.POST, decoy, String.class);
    }

    @Test
    void everyConcurrentTouchIsPersisted() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(THREADS);
        AtomicInteger okStatus = new AtomicInteger();
        AtomicInteger validBodies = new AtomicInteger();
        for (int t = 0; t < THREADS; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < CALLS_PER_THREAD; i++) {
                        ResponseEntity<String> response = rest.getForEntity(
                                url("/concurrent-target"), String.class);
                        if (response.getStatusCode().is2xxSuccessful()) {
                            okStatus.incrementAndGet();
                            if (isCompleteAndMarked(response.getBody())) {
                                validBodies.incrementAndGet();
                            }
                        }
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        int expected = THREADS * CALLS_PER_THREAD;
        assertEquals(expected, okStatus.get());
        assertEquals(expected, validBodies.get(),
                "every concurrent response must be complete, legal and carry the marker");

        long deadline = System.currentTimeMillis() + 15000;
        while (System.currentTimeMillis() < deadline) {
            if (countEvents(DECOY_ID) >= expected) {
                break;
            }
            Thread.sleep(200);
        }
        assertEquals(expected, countEvents(DECOY_ID),
                "every concurrent touch must be persisted");
    }

    private long countEvents(String decoyId) {
        String body = adminExchange("/admin/events?decoyId=" + decoyId,
                HttpMethod.GET, null, String.class).getBody();
        return body.split("eventId").length - 1L;
    }

    private boolean isCompleteAndMarked(String body) {
        try {
            JsonNode parsed = objectMapper.readTree(body);
            return "ok".equals(parsed.get("status").asText())
                    && body.contains(DECOY_ID)
                    && parsed.has("_honeypot_trace");
        } catch (Exception e) {
            return false;
        }
    }
}

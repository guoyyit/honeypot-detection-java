package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Alert;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrent touches from many sources must all be recorded and persisted;
 * de-duplication must still hold per (decoy, source).
 */
class ConcurrentTouchTests extends BaseHoneypotTests {

    private static final Path DATA_DIR = newTempDataDir();
    private static final int SOURCES = 8;
    private static final int TOUCHES_PER_SOURCE = 8;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.data-dir", DATA_DIR::toString);
        registry.add("honeypot.admin-token", () -> ADMIN_TOKEN);
    }

    @Test
    void concurrentTouchesAreAllRecordedAndDeduplicatedPerSource() throws Exception {
        Map<String, Object> decoy = Map.of(
                "id", "decoy-ep-concurrent",
                "path", "/internal/metrics-dump",
                "sensitivity", "MEDIUM");
        ResponseEntity<String> created = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), decoy, String.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ExecutorService pool = Executors.newFixedThreadPool(SOURCES);
        try {
            List<Callable<Integer>> tasks = new ArrayList<>();
            for (int source = 0; source < SOURCES; source++) {
                final String ip = "10.9.0." + source;
                tasks.add(() -> {
                    int ok = 0;
                    for (int i = 0; i < TOUCHES_PER_SOURCE; i++) {
                        HttpHeaders headers = new HttpHeaders();
                        headers.set("X-Forwarded-For", ip);
                        ResponseEntity<String> response = exchange("/internal/metrics-dump",
                                HttpMethod.GET, headers, null, String.class);
                        if (response.getStatusCode() == HttpStatus.OK) {
                            ok++;
                        }
                    }
                    return ok;
                });
            }
            List<Future<Integer>> results = new ArrayList<>();
            for (Callable<Integer> task : tasks) {
                results.add(pool.submit(task));
            }
            for (Future<Integer> result : results) {
                assertThat(result.get()).isEqualTo(TOUCHES_PER_SOURCE);
            }
        } finally {
            pool.shutdown();
        }

        awaitProcessing();

        int total = SOURCES * TOUCHES_PER_SOURCE;
        assertThat(eventStore.listAll())
                .as("every concurrent touch must be persisted, none lost")
                .hasSize(total);
        assertThat(eventStore.listPending()).isEmpty();

        List<Alert> alerts = alertRepository.listAll();
        assertThat(alerts).as("one deduplicated alert per source").hasSize(SOURCES);
        assertThat(alerts).allSatisfy(alert -> {
            assertThat(alert.touchCount).isEqualTo(TOUCHES_PER_SOURCE);
            assertThat(alert.level.name()).isEqualTo("WARNING");
        });
        assertThat(notifier.notifications)
                .as("cooldown suppresses repeat notifications: exactly one per source")
                .hasSize(SOURCES);
    }
}

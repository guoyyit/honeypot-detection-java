package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertNotifier;
import com.github.guoyyit.honeypotdetectionjava.honeypot.event.TouchEventProcessor;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AlertRepository;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.AuditLog;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.TouchEventStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Base class for honeypot integration tests: real servlet container, temp data dir
 * (provided by subclasses via @DynamicPropertySource) and a capturing notifier.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(BaseHoneypotTests.TestBeans.class)
public abstract class BaseHoneypotTests {

    protected static final String ADMIN_TOKEN = "test-admin-token";

    @LocalServerPort
    protected int port;

    @Autowired
    protected TestRestTemplate rest;

    @Autowired
    protected TouchEventProcessor processor;

    @Autowired
    protected TouchEventStore eventStore;

    @Autowired
    protected AlertRepository alertRepository;

    @Autowired
    protected AuditLog auditLog;

    @Autowired
    protected CapturingAlertNotifier notifier;

    protected static Path newTempDataDir() {
        try {
            return Files.createTempDirectory("honeypot-it-");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    protected String url(String path) {
        return "http://localhost:" + port + path;
    }

    protected HttpHeaders adminHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Admin-Token", ADMIN_TOKEN);
        headers.set("X-Admin-Name", "tester");
        return headers;
    }

    protected <T> ResponseEntity<T> exchange(String path, HttpMethod method, HttpHeaders headers,
                                             Object body, Class<T> type) {
        return rest.exchange(url(path), method, new HttpEntity<>(body, headers), type);
    }

    protected void awaitProcessing() throws InterruptedException {
        if (!processor.awaitIdle(Duration.ofSeconds(15))) {
            throw new AssertionError("touch events were not fully processed in time");
        }
    }

    @TestConfiguration
    static class TestBeans {
        @Bean
        @Primary
        public CapturingAlertNotifier capturingAlertNotifier() {
            return new CapturingAlertNotifier();
        }
    }
}

package com.github.guoyyit.honeypotdetectionjava.tests;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.nio.file.Files;
import java.nio.file.Path;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "honeypot.admin-token=test-admin-token",
                "honeypot.alert-cooldown-millis=100000"
        })
public abstract class AbstractIntegrationTest {

    protected static final String ADMIN_TOKEN = "test-admin-token";

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.state-file", () -> System.getProperty("java.io.tmpdir")
                + "/honeypot-test-" + java.util.UUID.randomUUID() + "/state.json");
    }

    @LocalServerPort
    protected int port;

    protected final TestRestTemplate rest = new TestRestTemplate();

    protected String url(String path) {
        return "http://localhost:" + port + path;
    }

    protected HttpHeaders adminHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Admin-Token", ADMIN_TOKEN);
        headers.set("X-Admin-Actor", "tester");
        return headers;
    }

    protected <T> ResponseEntity<T> adminExchange(String path, HttpMethod method,
                                                  Object body, Class<T> responseType) {
        HttpHeaders headers = adminHeaders();
        HttpEntity<Object> entity = body != null ? new HttpEntity<>(body, headers)
                : new HttpEntity<>(headers);
        return rest.exchange(url(path), method, entity, responseType);
    }

    protected void waitUntil(Condition condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            if (condition.check()) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("condition not met before timeout");
    }

    @FunctionalInterface
    protected interface Condition {
        boolean check();
    }
}

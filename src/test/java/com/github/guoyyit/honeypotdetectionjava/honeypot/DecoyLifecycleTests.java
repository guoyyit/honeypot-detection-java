package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the full decoy lifecycle: create, duplicate rejection, enable/disable,
 * delete, admin authentication, audit trail, and simulated responses.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DecoyLifecycleTests extends BaseHoneypotTests {

    private static final Path DATA_DIR = newTempDataDir();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.data-dir", DATA_DIR::toString);
        registry.add("honeypot.admin-token", () -> ADMIN_TOKEN);
        registry.add("honeypot.legit-users.alice", () -> "alice-secret");
    }

    @Test
    @Order(1)
    void managementApiRequiresAdminToken() {
        ResponseEntity<String> noToken = rest.postForEntity(
                url("/api/honeypot/decoys/endpoints"), Map.of("path", "/x"), String.class);
        assertThat(noToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        HttpHeaders wrong = new HttpHeaders();
        wrong.set("X-Admin-Token", "wrong");
        ResponseEntity<String> wrongToken = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, wrong, Map.of("path", "/x"), String.class);
        assertThat(wrongToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Order(2)
    void createEndpointDecoy() {
        Map<String, Object> body = Map.of(
                "id", "decoy-ep-1",
                "path", "/internal/debug-info",
                "sensitivity", "HIGH",
                "responseStatus", 200,
                "contentType", "application/json",
                "responseBody", "{\"version\":\"9.9.9\"}");
        ResponseEntity<String> response = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), body, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    @Order(3)
    void duplicateDecoysAreRejected() {
        Map<String, Object> samePath = Map.of("path", "/internal/debug-info");
        ResponseEntity<String> byPath = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), samePath, String.class);
        assertThat(byPath.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        Map<String, Object> sameId = Map.of("id", "decoy-ep-1", "path", "/other-path");
        ResponseEntity<String> byId = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), sameId, String.class);
        assertThat(byId.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        Map<String, Object> badPath = Map.of("path", "no-leading-slash");
        ResponseEntity<String> invalid = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), badPath, String.class);
        assertThat(invalid.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        Map<String, Object> shadowing = Map.of("path", "/api/honeypot/decoys");
        ResponseEntity<String> shadow = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), shadowing, String.class);
        assertThat(shadow.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @Order(4)
    void touchingEnabledDecoyReturnsSimulatedResponseWithMarker() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", "203.0.113.7");
        ResponseEntity<String> response = exchange("/internal/debug-info",
                HttpMethod.GET, headers, null, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"version\":\"9.9.9\"");
        assertThat(response.getBody()).contains("\"_trace\":\"hp:decoy-ep-1:evt-");

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(1);
        assertThat(alertRepository.listAll()).hasSize(1);
        assertThat(alertRepository.listAll().get(0).decoyId).isEqualTo("decoy-ep-1");
    }

    @Test
    @Order(5)
    void disabledDecoyProducesNoTouchEvent() throws Exception {
        ResponseEntity<String> disable = exchange("/api/honeypot/decoys/endpoints/decoy-ep-1/disable",
                HttpMethod.POST, adminHeaders(), null, String.class);
        assertThat(disable.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> touch = rest.getForEntity(url("/internal/debug-info"), String.class);
        assertThat(touch.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(1); // unchanged
    }

    @Test
    @Order(6)
    void reenabledDecoyAlertsAgain() throws Exception {
        exchange("/api/honeypot/decoys/endpoints/decoy-ep-1/enable",
                HttpMethod.POST, adminHeaders(), null, String.class);
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", "203.0.113.8");
        ResponseEntity<String> touch = exchange("/internal/debug-info",
                HttpMethod.GET, headers, null, String.class);
        assertThat(touch.getStatusCode()).isEqualTo(HttpStatus.OK);

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(2);
    }

    @Test
    @Order(7)
    void deletedDecoyProducesNoTouchEvent() throws Exception {
        ResponseEntity<String> delete = exchange("/api/honeypot/decoys/endpoints/decoy-ep-1",
                HttpMethod.DELETE, adminHeaders(), null, String.class);
        assertThat(delete.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> touch = rest.getForEntity(url("/internal/debug-info"), String.class);
        assertThat(touch.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        ResponseEntity<String> deleteAgain = exchange("/api/honeypot/decoys/endpoints/decoy-ep-1",
                HttpMethod.DELETE, adminHeaders(), null, String.class);
        assertThat(deleteAgain.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(2); // unchanged
    }

    @Test
    @Order(8)
    void credentialLifecycleIsAudited() {
        Map<String, Object> body = Map.of(
                "id", "decoy-cred-1", "username", "svc_backup", "secret", "s3cret");
        ResponseEntity<String> created = exchange("/api/honeypot/decoys/credentials",
                HttpMethod.POST, adminHeaders(), body, String.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<String> duplicate = exchange("/api/honeypot/decoys/credentials",
                HttpMethod.POST, adminHeaders(), body, String.class);
        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        assertThat(exchange("/api/honeypot/decoys/credentials/decoy-cred-1/disable",
                HttpMethod.POST, adminHeaders(), null, String.class).getStatusCode())
                .isEqualTo(HttpStatus.OK);
        assertThat(exchange("/api/honeypot/decoys/credentials/decoy-cred-1/enable",
                HttpMethod.POST, adminHeaders(), null, String.class).getStatusCode())
                .isEqualTo(HttpStatus.OK);
        assertThat(exchange("/api/honeypot/decoys/credentials/decoy-cred-1",
                HttpMethod.DELETE, adminHeaders(), null, String.class).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    @Order(9)
    void managementOperationsAreAudited() {
        List<AuditRecord> audit = auditLog.listAll();
        assertThat(audit).extracting(r -> r.action)
                .contains("CREATE_ENDPOINT", "DISABLE_ENDPOINT", "ENABLE_ENDPOINT",
                        "DELETE_ENDPOINT", "CREATE_CREDENTIAL", "DISABLE_CREDENTIAL",
                        "ENABLE_CREDENTIAL", "DELETE_CREDENTIAL");
        assertThat(audit).allSatisfy(r -> {
            assertThat(r.operator).isEqualTo("tester");
            assertThat(r.occurredAt).isPositive();
        });
    }

    @Test
    @Order(10)
    void normalTrafficIsNotAffected() {
        ResponseEntity<String> health = rest.getForEntity(url("/health"), String.class);
        assertThat(health.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> ping = rest.getForEntity(url("/api/business/ping"), String.class);
        assertThat(ping.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ping.getBody()).contains("ok");
    }
}

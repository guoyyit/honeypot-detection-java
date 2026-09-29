package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyType;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
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
 * Decoy credentials must generate a touch event on any authentication attempt,
 * regardless of the outcome, without disturbing the normal authentication path.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DecoyCredentialTests extends BaseHoneypotTests {

    private static final Path DATA_DIR = newTempDataDir();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.data-dir", DATA_DIR::toString);
        registry.add("honeypot.admin-token", () -> ADMIN_TOKEN);
        registry.add("honeypot.legit-users.alice", () -> "alice-secret");
    }

    @Test
    @Order(1)
    void registerDecoyCredential() {
        Map<String, Object> body = Map.of(
                "id", "decoy-cred-it",
                "username", "root_backup",
                "secret", "Sup3rSecret!",
                "sensitivity", "HIGH");
        ResponseEntity<String> created = exchange("/api/honeypot/decoys/credentials",
                HttpMethod.POST, adminHeaders(), body, String.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    @Order(2)
    void decoyCredentialWithWrongSecretStillGeneratesEvent() throws Exception {
        ResponseEntity<String> login = login("root_backup", "totally-wrong", "198.51.100.9");
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        awaitProcessing();
        assertThat(credentialEvents()).hasSize(1);
        TouchEvent event = credentialEvents().get(0);
        assertThat(event.decoyId).isEqualTo("decoy-cred-it");
        assertThat(event.source).isEqualTo("198.51.100.9");
        assertThat(event.detail).contains("secret mismatch");
        assertThat(alertRepository.listAll()).hasSize(1);
        assertThat(alertRepository.listAll().get(0).level.name()).isEqualTo("CRITICAL");
    }

    @Test
    @Order(3)
    void decoyCredentialWithCorrectSecretAlsoGeneratesEvent() throws Exception {
        ResponseEntity<String> login = login("root_backup", "Sup3rSecret!", "198.51.100.10");
        // Not a legitimate user, so still rejected - but the touch is recorded either way.
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        awaitProcessing();
        assertThat(credentialEvents()).hasSize(2);
        assertThat(credentialEvents().get(1).detail).contains("secret matched");
    }

    @Test
    @Order(4)
    void legitimateUserLoginGeneratesNoEvent() throws Exception {
        ResponseEntity<String> login = login("alice", "alice-secret", "203.0.113.20");
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);

        awaitProcessing();
        assertThat(credentialEvents()).hasSize(2);
    }

    @Test
    @Order(5)
    void unknownUserLoginGeneratesNoEvent() throws Exception {
        ResponseEntity<String> login = login("mallory", "whatever", "203.0.113.21");
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        awaitProcessing();
        assertThat(credentialEvents()).hasSize(2);
    }

    @Test
    @Order(6)
    void disabledDecoyCredentialGeneratesNoEvent() throws Exception {
        ResponseEntity<String> disable = exchange("/api/honeypot/decoys/credentials/decoy-cred-it/disable",
                HttpMethod.POST, adminHeaders(), null, String.class);
        assertThat(disable.getStatusCode()).isEqualTo(HttpStatus.OK);

        login("root_backup", "Sup3rSecret!", "198.51.100.11");
        awaitProcessing();
        assertThat(credentialEvents()).hasSize(2);
    }

    private ResponseEntity<String> login(String username, String password, String sourceIp) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", sourceIp);
        return exchange("/api/auth/login", HttpMethod.POST, headers,
                Map.of("username", username, "password", password), String.class);
    }

    private List<TouchEvent> credentialEvents() {
        return eventStore.listAll().stream()
                .filter(e -> e.decoyType == DecoyType.CREDENTIAL)
                .toList();
    }
}

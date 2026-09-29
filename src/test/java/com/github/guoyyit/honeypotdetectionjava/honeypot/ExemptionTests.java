package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.AuditRecord;
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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exemption rules suppress alerts for known-benign traffic (health checks,
 * internal jobs) but the touch evidence is always retained; rule changes are audited.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ExemptionTests extends BaseHoneypotTests {

    private static final Path DATA_DIR = newTempDataDir();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("honeypot.data-dir", DATA_DIR::toString);
        registry.add("honeypot.admin-token", () -> ADMIN_TOKEN);
    }

    @Test
    @Order(1)
    void registerDecoy() {
        Map<String, Object> decoy = Map.of(
                "id", "decoy-ep-exempt",
                "path", "/internal/cluster-status",
                "sensitivity", "LOW");
        ResponseEntity<String> created = exchange("/api/honeypot/decoys/endpoints",
                HttpMethod.POST, adminHeaders(), decoy, String.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    @Order(2)
    void createExemptionRuleForInternalProbes() {
        Map<String, Object> rule = Map.of(
                "id", "exempt-internal-probe",
                "name", "internal health checker",
                "type", "SOURCE_IP_PREFIX",
                "pattern", "10.0.0.");
        ResponseEntity<String> created = exchange("/api/honeypot/exemptions",
                HttpMethod.POST, adminHeaders(), rule, String.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    @Order(3)
    void exemptedTouchKeepsEvidenceButRaisesNoAlert() throws Exception {
        ResponseEntity<String> touch = touch("10.0.0.15");
        assertThat(touch.getStatusCode()).isEqualTo(HttpStatus.OK);

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(1);
        TouchEvent event = eventStore.listAll().get(0);
        assertThat(event.exempted).as("evidence is retained, flagged as exempted").isTrue();
        assertThat(event.exemptionRuleId).isEqualTo("exempt-internal-probe");
        assertThat(alertRepository.listAll()).isEmpty();
        assertThat(notifier.notifications).isEmpty();
    }

    @Test
    @Order(4)
    void nonExemptedAttackStillAlerts() throws Exception {
        ResponseEntity<String> touch = touch("203.0.113.66");
        assertThat(touch.getStatusCode()).isEqualTo(HttpStatus.OK);

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(2);
        assertThat(alertRepository.listAll()).hasSize(1);
        assertThat(alertRepository.listAll().get(0).source).isEqualTo("203.0.113.66");
        assertThat(alertRepository.listAll().get(0).level.name()).isEqualTo("INFO");
        assertThat(notifier.notifications).hasSize(1);
    }

    @Test
    @Order(5)
    void ruleChangesAreAudited() {
        Map<String, Object> update = Map.of(
                "name", "internal health checker v2",
                "type", "SOURCE_IP_PREFIX",
                "pattern", "10.0.0.",
                "enabled", true);
        ResponseEntity<String> updated = exchange("/api/honeypot/exemptions/exempt-internal-probe",
                HttpMethod.PUT, adminHeaders(), update, String.class);
        assertThat(updated.getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(auditLog.listAll()).extracting(r -> r.action)
                .contains("CREATE_EXEMPTION", "UPDATE_EXEMPTION");
        assertThat(auditLog.listAll()).filteredOn(r -> r.action.startsWith("CREATE_EXEMPTION"))
                .extracting(r -> r.operator).containsOnly("tester");
    }

    @Test
    @Order(6)
    void deletedRuleStopsExempting() throws Exception {
        ResponseEntity<String> deleted = exchange("/api/honeypot/exemptions/exempt-internal-probe",
                HttpMethod.DELETE, adminHeaders(), null, String.class);
        assertThat(deleted.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> touch = touch("10.0.0.16");
        assertThat(touch.getStatusCode()).isEqualTo(HttpStatus.OK);

        awaitProcessing();
        assertThat(eventStore.listAll()).hasSize(3);
        TouchEvent event = eventStore.listAll().get(2);
        assertThat(event.exempted).isFalse();
        assertThat(alertRepository.listAll()).hasSize(2);
        assertThat(auditLog.listAll()).extracting(r -> r.action).contains("DELETE_EXEMPTION");
    }

    @Test
    @Order(7)
    void exemptionManagementRequiresAdminToken() {
        ResponseEntity<String> noToken = rest.postForEntity(url("/api/honeypot/exemptions"),
                Map.of("type", "SOURCE_IP_PREFIX", "pattern", "10."), String.class);
        assertThat(noToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private ResponseEntity<String> touch(String sourceIp) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", sourceIp);
        return exchange("/internal/cluster-status", HttpMethod.GET, headers, null, String.class);
    }
}

package com.github.guoyyit.honeypotdetectionjava.honeypot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.honeypotdetectionjava.honeypot.detection.SimulatedResponseRenderer;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every simulated response must carry a traceable internal marker
 * and must not leak real data.
 */
class SimulatedResponseRendererTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SimulatedResponseRenderer renderer = new SimulatedResponseRenderer(mapper);

    @Test
    void jsonResponseCarriesTraceMarker() throws Exception {
        DecoyEndpoint decoy = decoy("application/json", "{\"status\":\"ok\"}");
        TouchEvent event = event("evt-123");

        String body = renderer.render(decoy, event);

        JsonNode node = mapper.readTree(body);
        assertThat(node.get("status").asText()).isEqualTo("ok");
        assertThat(node.get("_trace").asText()).isEqualTo("hp:decoy-ep-t:evt-123");
    }

    @Test
    void htmlResponseCarriesTraceComment() {
        DecoyEndpoint decoy = decoy("text/html", "<html><body>Welcome</body></html>");
        String body = renderer.render(decoy, event("evt-9"));
        assertThat(body).contains("Welcome");
        assertThat(body).contains("<!-- hp:decoy-ep-t:evt-9 -->");
    }

    @Test
    void plainTextResponseCarriesTraceLine() {
        DecoyEndpoint decoy = decoy("text/plain", "OK");
        String body = renderer.render(decoy, event("evt-5"));
        assertThat(body).contains("OK");
        assertThat(body).contains("hp:decoy-ep-t:evt-5");
    }

    @Test
    void invalidJsonBodyIsWrappedWithMarker() throws Exception {
        DecoyEndpoint decoy = decoy("application/json", "not-json-at-all");
        String body = renderer.render(decoy, event("evt-7"));
        JsonNode node = mapper.readTree(body);
        assertThat(node.get("_trace").asText()).isEqualTo("hp:decoy-ep-t:evt-7");
    }

    @Test
    void markerContainsDecoyAndEventIdsForTraceability() {
        DecoyEndpoint decoy = decoy("application/json", "{}");
        TouchEvent event = event("evt-abc");
        String marker = renderer.marker(decoy, event);
        assertThat(marker).contains("decoy-ep-t").contains("evt-abc");
    }

    private DecoyEndpoint decoy(String contentType, String body) {
        DecoyEndpoint decoy = new DecoyEndpoint();
        decoy.id = "decoy-ep-t";
        decoy.path = "/t";
        decoy.contentType = contentType;
        decoy.responseBody = body;
        return decoy;
    }

    private TouchEvent event(String id) {
        TouchEvent event = new TouchEvent();
        event.id = id;
        return event;
    }
}

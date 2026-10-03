package com.github.guoyyit.honeypotdetectionjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DecoyResponseContentTypeTest extends AbstractIntegrationTest {

    private static final String MARKER_PREFIX = "HONEYPOT-INTERNAL-MARKER";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    void setUp() {
        register("ct-json", "/ct-json", "application/json",
                "{\"service\":\"fake-api\",\"version\":7}");
        register("ct-json-charset", "/ct-json-charset", "application/json;charset=UTF-8",
                "{\"service\":\"fake-api\",\"version\":7}");
        register("ct-html", "/ct-html", "text/html",
                "<html><body>login</body></html>");
        register("ct-text", "/ct-text", "text/plain",
                "AUTHORIZED USE ONLY");
        register("ct-empty", "/ct-empty", "application/json", "");
        register("ct-none", "/ct-none", null,
                "{\"service\":\"fake-api\",\"version\":7}");
        register("ct-bad", "/ct-bad", "not-a-content-type",
                "RAW-SIMULATION-CONTENT");
    }

    private void register(String id, String path, String contentType, String body) {
        Map<String, Object> simulation = new LinkedHashMap<>();
        simulation.put("statusCode", 200);
        if (contentType != null) {
            simulation.put("contentType", contentType);
        }
        simulation.put("body", body);
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", id,
                "name", id,
                "type", "HTTP_ENDPOINT",
                "sensitivity", 1,
                "path", path,
                "simulatedResponse", simulation), String.class);
    }

    @Test
    void applicationJsonBodyIsStrictlyParseableAndCarriesMarker() throws Exception {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-json"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        MediaType responseType = MediaType.parseMediaType(
                response.getHeaders().getFirst("Content-Type"));
        assertTrue(responseType.includes(MediaType.APPLICATION_JSON));

        JsonNode parsed = objectMapper.readTree(response.getBody());
        assertEquals("fake-api", parsed.get("service").asText());
        assertEquals(7, parsed.get("version").asInt());
        assertNotNull(parsed.get("_honeypot_trace"));
        assertMarkerHeader(response, "ct-json");
        assertTouchRecorded("ct-json");
    }

    @Test
    void applicationJsonWithCharsetParameterIsParseableAndCarriesMarker() throws Exception {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-json-charset"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        MediaType responseType = MediaType.parseMediaType(
                response.getHeaders().getFirst("Content-Type"));
        assertTrue(responseType.includes(MediaType.APPLICATION_JSON));

        JsonNode parsed = objectMapper.readTree(response.getBody());
        assertEquals("fake-api", parsed.get("service").asText());
        assertEquals(7, parsed.get("version").asInt());
        assertNotNull(parsed.get("_honeypot_trace"));
        assertMarkerHeader(response, "ct-json-charset");
        assertTouchRecorded("ct-json-charset");
    }

    @Test
    void textHtmlBodyCarriesMarkerAsComment() {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-html"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        MediaType responseType = MediaType.parseMediaType(
                response.getHeaders().getFirst("Content-Type"));
        assertTrue(responseType.includes(MediaType.TEXT_HTML));
        String body = response.getBody();
        assertTrue(body.contains("<html><body>login</body></html>"),
                "configured content must be fully preserved");
        assertTrue(body.contains("<!--"));
        assertTrue(body.contains("ct-html"));
        assertMarkerHeader(response, "ct-html");
        assertTouchRecorded("ct-html");
    }

    @Test
    void textPlainBodyCarriesMarker() {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-text"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        MediaType responseType = MediaType.parseMediaType(
                response.getHeaders().getFirst("Content-Type"));
        assertTrue(responseType.includes(MediaType.TEXT_PLAIN));
        String body = response.getBody();
        assertTrue(body.contains("AUTHORIZED USE ONLY"),
                "configured content must be fully preserved");
        assertTrue(body.contains("ct-text"));
        assertMarkerHeader(response, "ct-text");
        assertTouchRecorded("ct-text");
    }

    @Test
    void emptyBodyWithJsonTypeIsParseableAndCarriesMarker() throws Exception {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-empty"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        MediaType responseType = MediaType.parseMediaType(
                response.getHeaders().getFirst("Content-Type"));
        assertTrue(responseType.includes(MediaType.APPLICATION_JSON));

        JsonNode parsed = objectMapper.readTree(response.getBody());
        assertNotNull(parsed.get("_honeypot_trace"));
        assertTrue(response.getBody().contains("ct-empty"));
        assertMarkerHeader(response, "ct-empty");
        assertTouchRecorded("ct-empty");
    }

    @Test
    void missingContentTypeDefaultsToJsonAndIsParseable() throws Exception {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-none"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        MediaType responseType = MediaType.parseMediaType(
                response.getHeaders().getFirst("Content-Type"));
        assertTrue(responseType.includes(MediaType.APPLICATION_JSON));

        JsonNode parsed = objectMapper.readTree(response.getBody());
        assertEquals("fake-api", parsed.get("service").asText());
        assertEquals(7, parsed.get("version").asInt());
        assertNotNull(parsed.get("_honeypot_trace"));
        assertMarkerHeader(response, "ct-none");
        assertTouchRecorded("ct-none");
    }

    @Test
    void unparseableContentTypeFallsBackSafelyWithoutServerError() {
        ResponseEntity<String> response = rest.getForEntity(url("/ct-bad"), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode(),
                "unparseable content type must not cause a server error");
        String body = response.getBody();
        assertTrue(body.contains("RAW-SIMULATION-CONTENT"),
                "configured content must still be returned");
        assertTrue(body.contains("ct-bad"));
        assertMarkerHeader(response, "ct-bad");
        assertTouchRecorded("ct-bad");
    }

    private void assertMarkerHeader(ResponseEntity<String> response, String decoyId) {
        String trace = response.getHeaders().getFirst("X-Honeypot-Trace");
        assertNotNull(trace);
        assertEquals(MARKER_PREFIX + ":" + decoyId, trace);
    }

    private void assertTouchRecorded(String decoyId) {
        String events = adminExchange("/admin/events?decoyId=" + decoyId,
                HttpMethod.GET, null, String.class).getBody();
        assertTrue(events.contains("\"decoyId\":\"" + decoyId + "\""),
                "admin side must be able to correlate the marker with the touch event");
    }
}

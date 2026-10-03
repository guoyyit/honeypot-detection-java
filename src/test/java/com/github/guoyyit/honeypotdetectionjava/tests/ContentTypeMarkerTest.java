package com.github.guoyyit.honeypotdetectionjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.swing.text.Document;
import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentTypeMarkerTest extends AbstractIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TRACE_FIELD = "_honeypot_trace";
    private static final String MARKER_PREFIX = "HONEYPOT-INTERNAL-MARKER:";

    @Test
    void jsonBodyStaysStrictlyParseableAndKeepsConfiguredContentPlusMarker() throws Exception {
        createEndpoint("ct-json", "/ct-json", "application/json",
                "{\"service\":\"billing\",\"version\":3}");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-json"), String.class);
        assertEquals(MediaType.APPLICATION_JSON,
                response.getHeaders().getContentType(),
                "declared content type must be preserved");

        JsonNode parsed = JSON.readTree(response.getBody());
        assertTrue(parsed.isObject(), "body must parse as a JSON object");
        assertEquals("billing", parsed.path("service").asText(),
                "configured content must be fully retained");
        assertEquals(3, parsed.path("version").asInt());
        assertTraceComplete(response, parsed.path(TRACE_FIELD).asText(), "ct-json");
    }

    @Test
    void jsonWithCharsetParameterStaysStrictlyParseable() throws Exception {
        createEndpoint("ct-json-charset", "/ct-json-charset",
                "application/json; charset=utf-8",
                "{\"ok\":true,\"items\":[1,2,3]}");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-json-charset"), String.class);
        assertNotNull(response.getHeaders().getContentType());
        assertEquals("application", response.getHeaders().getContentType().getType());
        assertEquals("json", response.getHeaders().getContentType().getSubtype());

        JsonNode parsed = JSON.readTree(response.getBody());
        assertTrue(parsed.path("ok").asBoolean());
        assertEquals(3, parsed.path("items").size(), "all configured JSON elements are retained");
        assertTraceComplete(response, parsed.path(TRACE_FIELD).asText(), "ct-json-charset");
    }

    @Test
    void jsonArrayBodyKeepsEveryElementAndCarriesMarker() throws Exception {
        createEndpoint("ct-json-array", "/ct-json-array", "application/json",
                "[{\"id\":\"a\"},{\"id\":\"b\"}]");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-json-array"), String.class);
        JsonNode parsed = JSON.readTree(response.getBody());
        assertTrue(parsed.isArray());
        assertEquals("a", parsed.get(0).path("id").asText());
        assertEquals("b", parsed.get(1).path("id").asText());
        JsonNode markerNode = parsed.get(parsed.size() - 1).path(TRACE_FIELD);
        assertFalse(markerNode.isMissingNode(), "marker is embedded inside the JSON array");
        assertTraceComplete(response, markerNode.asText(), "ct-json-array");
    }

    @Test
    void htmlBodyStaysParsableAndKeepsConfiguredContentPlusMarker() throws Exception {
        String configuredBody = "<html><head><title>login</title></head>"
                + "<body><form>user: <input></form></body></html>";
        createEndpoint("ct-html", "/ct-html", "text/html", configuredBody);

        ResponseEntity<String> response = rest.getForEntity(url("/ct-html"), String.class);
        MediaType type = response.getHeaders().getContentType();
        assertNotNull(type);
        assertEquals("text", type.getType());
        assertEquals("html", type.getSubtype());

        Document document = parseHtml(response.getBody());
        String extractedText = document.getText(0, document.getLength());
        assertTrue(extractedText.contains("user:"),
                "configured HTML content must be fully retained");

        List<String> comments = extractHtmlComments(response.getBody());
        assertTrue(comments.stream().anyMatch(c -> c.contains(MARKER_PREFIX + "ct-html")),
                "trace marker must be embedded as a parseable HTML comment");
        assertTraceComplete(response, MARKER_PREFIX + "ct-html", "ct-html");
    }

    @Test
    void plainTextBodyStaysReadableAndCarriesMarker() throws Exception {
        createEndpoint("ct-text", "/ct-text", "text/plain", "plain simulated output line");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-text"), String.class);
        MediaType type = response.getHeaders().getContentType();
        assertNotNull(type);
        assertEquals("text", type.getType());
        assertEquals("plain", type.getSubtype());

        String body = response.getBody();
        assertTrue(body.startsWith("plain simulated output line"),
                "configured text must be fully retained and appear first");
        String marker = body.substring(body.indexOf('\n') + 1).trim();
        assertTraceComplete(response, marker, "ct-text");
    }

    @Test
    void emptyBodyStillReturnsLegalContentCarryingMarker() throws Exception {
        createEndpoint("ct-empty", "/ct-empty", "application/json", "");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-empty"), String.class);
        JsonNode parsed = JSON.readTree(response.getBody());
        assertTrue(parsed.isObject(), "empty body becomes a legal JSON object");
        assertTraceComplete(response, parsed.path(TRACE_FIELD).asText(), "ct-empty");
    }

    @Test
    void missingContentTypeDefaultsToJsonAndBodyIsParseableWithMarker() throws Exception {
        adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", "ct-no-type",
                "name", "no content type",
                "type", "HTTP_ENDPOINT",
                "sensitivity", 1,
                "path", "/ct-no-type",
                "simulatedResponse", Map.of(
                        "statusCode", 200,
                        "body", "{\"defaulted\":true}")), String.class);

        ResponseEntity<String> response = rest.getForEntity(url("/ct-no-type"), String.class);
        assertEquals(MediaType.APPLICATION_JSON,
                response.getHeaders().getContentType(),
                "missing content type defaults to application/json");
        JsonNode parsed = JSON.readTree(response.getBody());
        assertTrue(parsed.path("defaulted").asBoolean(), "configured content is retained");
        assertTraceComplete(response, parsed.path(TRACE_FIELD).asText(), "ct-no-type");
    }

    @Test
    void unparseableContentTypeDoesNotErrorAndStillReturnsParseableMarkedBody() {
        createEndpoint("ct-bad-type", "/ct-bad-type", "not-a-valid-type!!!",
                "raw simulation payload");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-bad-type"), String.class);
        assertEquals(200, response.getStatusCode().value(),
                "unparseable content type must not cause a server error");
        MediaType type = response.getHeaders().getContentType();
        assertNotNull(type, "a safe fallback content type is returned");
        assertEquals("text", type.getType());
        assertEquals("plain", type.getSubtype());

        String body = response.getBody();
        assertTrue(body.contains("raw simulation payload"),
                "configured content is still served");
        String headerMarker = response.getHeaders().getFirst("X-Honeypot-Trace");
        assertNotNull(headerMarker);
        assertTrue(headerMarker.endsWith(":ct-bad-type"));
        assertTrue(body.contains(headerMarker),
                "body marker must carry the full trace including decoy id");
    }

    @Test
    void malformedJsonBodyFallsBackToLegalJsonWithoutLosingContent() throws Exception {
        createEndpoint("ct-bad-json", "/ct-bad-json", "application/json",
                "{this is not valid json");

        ResponseEntity<String> response = rest.getForEntity(url("/ct-bad-json"), String.class);
        assertEquals(200, response.getStatusCode().value());
        JsonNode parsed = JSON.readTree(response.getBody());
        assertTrue(parsed.isObject());
        assertTrue(parsed.path("body").asText().contains("this is not valid json"),
                "the originally configured text is preserved verbatim");
        assertTraceComplete(response, parsed.path(TRACE_FIELD).asText(), "ct-bad-json");
    }

    private void assertTraceComplete(ResponseEntity<String> response, String bodyMarker,
                                    String decoyId) {
        String headerMarker = response.getHeaders().getFirst("X-Honeypot-Trace");
        assertNotNull(headerMarker, "trace header must be present for every content type");
        assertTrue(headerMarker.contains(decoyId),
                "trace marker must contain the decoy id for admin-side correlation");
        assertTrue(headerMarker.startsWith(MARKER_PREFIX),
                "trace marker must contain the configured internal marker prefix");
        assertEquals(headerMarker, bodyMarker,
                "body marker and header marker must match exactly");
    }

    private void createEndpoint(String id, String path, String contentType, String body) {
        ResponseEntity<String> created = adminExchange("/admin/decoys", HttpMethod.POST, Map.of(
                "id", id,
                "name", id,
                "type", "HTTP_ENDPOINT",
                "sensitivity", 0,
                "path", path,
                "simulatedResponse", Map.of(
                        "statusCode", 200,
                        "contentType", contentType,
                        "body", body)), String.class);
        assertTrue(created.getStatusCode().is2xxSuccessful());
    }

    private Document parseHtml(String html) throws Exception {
        HTMLEditorKit kit = new HTMLEditorKit();
        Document document = kit.createDefaultDocument();
        kit.read(new StringReader(html), document, 0);
        return document;
    }

    private List<String> extractHtmlComments(String html) throws Exception {
        List<String> comments = new ArrayList<>();
        new ParserDelegator().parse(new StringReader(html),
                new HTMLEditorKit.ParserCallback() {
                    @Override
                    public void handleComment(char[] data, int pos) {
                        comments.add(new String(data));
                    }

                    @Override
                    public void handleText(char[] data, int pos) {
                        // No-op: text content is verified via the parsed Document.
                    }

                    @Override
                    public void handleStartTag(
                            javax.swing.text.html.HTML.Tag tag,
                            MutableAttributeSet attr, int pos) {
                        // No-op.
                    }
                }, true);
        return comments;
    }
}

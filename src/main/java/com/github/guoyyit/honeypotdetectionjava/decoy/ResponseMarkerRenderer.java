package com.github.guoyyit.honeypotdetectionjava.decoy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

/**
 * Renders a simulated decoy response body while embedding the internal trace
 * marker in a way that keeps the body strictly parseable under the declared
 * content type.
 */
@Component
public class ResponseMarkerRenderer {

    public static final String DEFAULT_CONTENT_TYPE = "application/json";
    public static final String TRACE_FIELD = "_honeypot_trace";
    public static final String FALLBACK_CONTENT_TYPE = "text/plain;charset=UTF-8";

    public record RenderedResponse(String contentType, String body) {
    }

    private final ObjectMapper objectMapper;

    public ResponseMarkerRenderer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public RenderedResponse render(SimulatedResponse simulation, String traceMarker) {
        String safeBody = simulation.getBody() != null ? simulation.getBody() : "";
        try {
            String configuredType = simulation.getContentType() != null
                    && !simulation.getContentType().isBlank()
                    ? simulation.getContentType().trim() : DEFAULT_CONTENT_TYPE;

            // Validates the full media type (including parameters) is syntactically legal.
            org.springframework.http.MediaType mediaType =
                    org.springframework.http.MediaType.parseMediaType(configuredType);
            String baseType = (mediaType.getType() + "/" + mediaType.getSubtype())
                    .toLowerCase();

            String embeddedBody;
            if ("application/json".equals(baseType)) {
                embeddedBody = embedInJson(safeBody, traceMarker);
            } else if ("text/html".equals(baseType)) {
                embeddedBody = embedInHtml(safeBody, traceMarker);
            } else {
                embeddedBody = embedAsText(safeBody, traceMarker);
            }
            return new RenderedResponse(configuredType, embeddedBody);
        } catch (RuntimeException invalidType) {
            return new RenderedResponse(FALLBACK_CONTENT_TYPE,
                    embedAsText(safeBody, traceMarker));
        } catch (Exception renderFailure) {
            // Rendering must never surface a server error: keep the simulation parsable.
            return new RenderedResponse(FALLBACK_CONTENT_TYPE,
                    embedAsText(safeBody, traceMarker));
        }
    }

    private String embedInJson(String body, String traceMarker) {
        if (body.isBlank()) {
            ObjectNode traceOnly = objectMapper.createObjectNode();
            traceOnly.put(TRACE_FIELD, traceMarker);
            return writeJson(traceOnly);
        }
        try {
            JsonNode parsed = objectMapper.readTree(body);
            if (parsed == null || parsed.isNull() || !parsed.isContainerNode()) {
                ObjectNode wrapped = objectMapper.createObjectNode();
                wrapped.set("value", parsed == null ? objectMapper.nullNode() : parsed);
                wrapped.put(TRACE_FIELD, traceMarker);
                return writeJson(wrapped);
            }
            if (parsed.isObject()) {
                ((ObjectNode) parsed).put(TRACE_FIELD, traceMarker);
                return writeJson(parsed);
            }
            if (parsed.isArray()) {
                ObjectNode traceElement = objectMapper.createObjectNode();
                traceElement.put(TRACE_FIELD, traceMarker);
                ((com.fasterxml.jackson.databind.node.ArrayNode) parsed).add(traceElement);
                return writeJson(parsed);
            }
            ObjectNode wrapped = objectMapper.createObjectNode();
            wrapped.set("value", parsed);
            wrapped.put(TRACE_FIELD, traceMarker);
            return writeJson(wrapped);
        } catch (Exception notJson) {
            ObjectNode fallback = objectMapper.createObjectNode();
            fallback.put("body", body);
            fallback.put(TRACE_FIELD, traceMarker);
            return writeJson(fallback);
        }
    }

    private String writeJson(JsonNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to render JSON simulation", e);
        }
    }

    private String embedInHtml(String body, String traceMarker) {
        // "--" is illegal inside an HTML comment, sanitize so the document stays well-formed.
        String safeMarker = traceMarker.replace("--", "-");
        String comment = "<!-- " + safeMarker + " -->";
        int closeIndex = body.lastIndexOf("</");
        if (closeIndex >= 0) {
            return body.substring(0, closeIndex) + comment + body.substring(closeIndex);
        }
        return body + comment;
    }

    private String embedAsText(String body, String traceMarker) {
        if (body.isEmpty()) {
            return traceMarker;
        }
        return body + System.lineSeparator() + traceMarker;
    }
}

package com.github.guoyyit.honeypotdetectionjava.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

/**
 * Embeds the trace marker into a simulated response body without breaking the
 * content type declared by the response header.
 *
 * <ul>
 *   <li>{@code application/json} (including {@code application/json;charset=...}
 *       and {@code *&#47;*+json}): the marker is added as a JSON field, so the
 *       body stays strictly parseable; the configured content is preserved.</li>
 *   <li>{@code text/html}: the marker is appended as an HTML comment.</li>
 *   <li>{@code text/plain} and other types}: the marker is appended as plain text.</li>
 *   <li>Empty body: the marker alone is returned in a type-legal form.</li>
 *   <li>Unparseable content type or a JSON body that is not actually JSON:
 *       the response falls back to a parseable type instead of failing.</li>
 * </ul>
 */
@Component
public class MarkerInjector {

    public static final String MARKER_FIELD = "_honeypot_trace";

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Injection inject(String body, String marker, String configuredContentType) {
        String safeBody = body != null ? body : "";
        MediaType mediaType = parse(configuredContentType);
        if (mediaType == null) {
            return new Injection(appendPlain(safeBody, marker), MediaType.TEXT_PLAIN_VALUE);
        }
        if (isJson(mediaType)) {
            return injectJson(safeBody, marker, mediaType);
        }
        if (isHtml(mediaType)) {
            String marked = safeBody.isEmpty()
                    ? "<!-- " + marker + " -->"
                    : safeBody + "<!-- " + marker + " -->";
            return new Injection(marked, mediaType.toString());
        }
        return new Injection(appendPlain(safeBody, marker), mediaType.toString());
    }

    private MediaType parse(String configuredContentType) {
        if (configuredContentType == null || configuredContentType.isBlank()) {
            return MediaType.APPLICATION_JSON;
        }
        try {
            return MediaType.parseMediaType(configuredContentType);
        } catch (InvalidMediaTypeException e) {
            return null;
        }
    }

    private boolean isJson(MediaType mediaType) {
        if (mediaType.includes(MediaType.APPLICATION_JSON)) {
            return true;
        }
        return mediaType.getSubtype().endsWith("+json");
    }

    private boolean isHtml(MediaType mediaType) {
        return mediaType.getSubtype().contains("html");
    }

    private Injection injectJson(String safeBody, String marker, MediaType mediaType) {
        if (safeBody.isBlank()) {
            ObjectNode node = objectMapper.createObjectNode();
            node.put(MARKER_FIELD, marker);
            return new Injection(write(node), mediaType.toString());
        }
        try {
            JsonNode root = objectMapper.readTree(safeBody);
            if (root.isObject()) {
                ((ObjectNode) root).put(MARKER_FIELD, marker);
                return new Injection(write(root), mediaType.toString());
            }
            ObjectNode wrapper = objectMapper.createObjectNode();
            wrapper.set("data", root);
            wrapper.put(MARKER_FIELD, marker);
            return new Injection(write(wrapper), mediaType.toString());
        } catch (JsonProcessingException e) {
            return new Injection(appendPlain(safeBody, marker), MediaType.TEXT_PLAIN_VALUE);
        }
    }

    private String write(JsonNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private String appendPlain(String body, String marker) {
        if (body.isEmpty()) {
            return marker;
        }
        return body + "\n" + marker;
    }

    public record Injection(String body, String contentType) {
    }
}

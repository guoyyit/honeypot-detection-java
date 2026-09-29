package com.github.guoyyit.honeypotdetectionjava.honeypot.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;

/**
 * Renders simulated responses for decoy endpoints. Every response carries an
 * internal traceable marker and never contains real data.
 */
public class SimulatedResponseRenderer {

    public static final String TRACE_FIELD = "_trace";

    private final ObjectMapper mapper;

    public SimulatedResponseRenderer(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public String render(DecoyEndpoint decoy, TouchEvent event) {
        String marker = marker(decoy, event);
        String contentType = decoy.contentType == null ? "" : decoy.contentType.toLowerCase();
        String body = decoy.responseBody == null ? "" : decoy.responseBody;
        if (contentType.contains("json")) {
            return injectJsonMarker(body, marker);
        }
        if (contentType.contains("html")) {
            return body + "\n<!-- " + marker + " -->\n";
        }
        return body + "\n" + marker + "\n";
    }

    public String marker(DecoyEndpoint decoy, TouchEvent event) {
        return "hp:" + decoy.id + ":" + event.id;
    }

    private String injectJsonMarker(String body, String marker) {
        try {
            JsonNode node = mapper.readTree(body);
            if (node instanceof ObjectNode object) {
                object.put(TRACE_FIELD, marker);
                return mapper.writeValueAsString(object);
            }
        } catch (Exception ignored) {
            // fall through to wrapper
        }
        ObjectNode wrapper = mapper.createObjectNode();
        wrapper.put("data", body);
        wrapper.put(TRACE_FIELD, marker);
        try {
            return mapper.writeValueAsString(wrapper);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to render simulated response", e);
        }
    }
}

package com.github.guoyyit.honeypotdetectionjava.honeypot.detection;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyEndpoint;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyType;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.honeypot.event.TouchEventService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.DecoyRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Intercepts requests to registered decoy endpoints, records a touch event and
 * returns a simulated response instead of hitting real business logic.
 */
public class DecoyEndpointFilter extends OncePerRequestFilter {

    private final DecoyRepository decoyRepository;
    private final TouchEventService touchEventService;
    private final SimulatedResponseRenderer renderer;

    public DecoyEndpointFilter(DecoyRepository decoyRepository, TouchEventService touchEventService,
                               SimulatedResponseRenderer renderer) {
        this.decoyRepository = decoyRepository;
        this.touchEventService = touchEventService;
        this.renderer = renderer;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Optional<DecoyEndpoint> decoy = decoyRepository.findEndpointByPath(request.getRequestURI());
        if (decoy.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }
        DecoyEndpoint endpoint = decoy.get();
        String source = extractSource(request);
        TouchEvent event = touchEventService.recordTouch(DecoyType.ENDPOINT, endpoint.id,
                endpoint.sensitivity, source, request.getRequestURI(),
                request.getHeader("User-Agent"),
                request.getMethod() + " " + request.getRequestURI());

        String body = renderer.render(endpoint, event);
        response.setStatus(endpoint.responseStatus);
        response.setContentType(endpoint.contentType);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(body);
    }

    public static String extractSource(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

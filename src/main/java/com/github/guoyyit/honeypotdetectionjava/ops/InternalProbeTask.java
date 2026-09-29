package com.github.guoyyit.honeypotdetectionjava.ops;

import com.github.guoyyit.honeypotdetectionjava.config.HoneypotProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@Component
public class InternalProbeTask {

    private static final Logger log = LoggerFactory.getLogger(InternalProbeTask.class);

    private final HoneypotProperties properties;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    public InternalProbeTask(HoneypotProperties properties) {
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${honeypot.internal-probe.interval-millis:0}")
    public void probe() {
        String baseUrl = properties.getInternalProbeBaseUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            return;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + properties.getHealthPath()))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.debug("Internal health probe failed: {}", e.getMessage());
        }
    }
}

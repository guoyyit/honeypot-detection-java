package com.github.guoyyit.honeypotdetectionjava.tests;

import com.github.guoyyit.honeypotdetectionjava.alert.Alert;
import com.github.guoyyit.honeypotdetectionjava.alert.AlertNotifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Primary
@ConditionalOnProperty(name = "honeypot.test.notifier-callback-url")
public class CapturingNotifier implements AlertNotifier {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    @Value("${honeypot.test.notifier-callback-url:}")
    private String callbackUrl;

    @Override
    public void notify(Alert alert) {
        if (callbackUrl == null || callbackUrl.isBlank()) {
            return;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(callbackUrl))
                    .timeout(Duration.ofSeconds(2))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception ignored) {
        }
    }
}

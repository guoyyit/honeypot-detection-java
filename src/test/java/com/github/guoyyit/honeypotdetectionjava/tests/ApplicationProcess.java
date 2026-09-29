package com.github.guoyyit.honeypotdetectionjava.tests;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

class ApplicationProcess implements AutoCloseable {

    private final Path stateFile;
    private final int port;
    private final HttpServer callbackServer;
    private final AtomicInteger notifications = new AtomicInteger();
    private Process process;

    ApplicationProcess(Path stateFile, int port) throws IOException {
        this.stateFile = stateFile;
        this.port = port;
        this.callbackServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        callbackServer.createContext("/notified", exchange -> {
            notifications.incrementAndGet();
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        callbackServer.start();
    }

    int notificationCount() {
        return notifications.get();
    }

    void startAndWaitReady() throws Exception {
        String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = System.getProperty("java.class.path");
        ProcessBuilder builder = new ProcessBuilder(
                javaBin,
                "-cp", classpath,
                "-Dspring.main.banner-mode=off",
                "com.github.guoyyit.honeypotdetectionjava.Application",
                "--server.port=" + port,
                "--honeypot.state-file=" + stateFile,
                "--honeypot.admin-token=proc-admin-token",
                "--honeypot.alert-cooldown-millis=100000",
                "--honeypot.test.notifier-callback-url=http://127.0.0.1:"
                        + callbackServer.getAddress().getPort() + "/notified");
        Path logFile = Files.createTempFile("honeypot-proc-", ".log");
        builder.redirectErrorStream(true);
        builder.redirectOutput(logFile.toFile());
        process = builder.start();
        long deadline = System.currentTimeMillis() + 60000;
        while (System.currentTimeMillis() < deadline) {
            try {
                HttpResponse<String> response = HttpClient.newHttpClient().send(
                        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/healthz"))
                                .GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    return;
                }
            } catch (Exception ignored) {
            }
            if (!process.isAlive()) {
                throw new IllegalStateException("Application exited early, log: " + logFile);
            }
            Thread.sleep(300);
        }
        throw new IllegalStateException("Application did not become ready, log: " + logFile);
    }

    void createEndpointDecoy(String id, String path, int sensitivity) {
        String json = """
                {"id":"%s","name":"%s","type":"HTTP_ENDPOINT","sensitivity":%d,"path":"%s",
                "simulatedResponse":{"statusCode":200,"contentType":"application/json","body":"{}"}}
                """.formatted(id, id, sensitivity, path);
        HttpResponse<String> response = admin("/admin/decoys", "POST", json);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("create decoy failed: " + response.statusCode()
                    + " " + response.body());
        }
    }

    void touch(String path, int times) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        for (int i = 0; i < times; i++) {
            client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                    .GET().build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    long waitForEventCount(long expected, long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (System.currentTimeMillis() < deadline) {
            String body = getEvents(null);
            long count = body.split("eventId").length - 1L;
            if (count >= expected && notifications.get() >= 1) {
                return count;
            }
            Thread.sleep(200);
        }
        throw new AssertionError("expected " + expected + " events, last notifications="
                + notifications.get());
    }

    long unprocessedEventCount() {
        String body = getEvents(null);
        return body.split("\"processed\":false").length - 1L;
    }

    String getEvents(String decoyId) {
        String path = "/admin/events" + (decoyId != null ? "?decoyId=" + decoyId : "");
        return admin(path, "GET", null).body();
    }

    String listDecoys() {
        return admin("/admin/decoys", "GET", null).body();
    }

    String listAlerts() {
        return admin("/admin/alerts", "GET", null).body();
    }

    private HttpResponse<String> admin(String path, String method, String jsonBody) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + port + path))
                    .header("X-Admin-Token", "proc-admin-token")
                    .header("X-Admin-Actor", "proc-test")
                    .header("Content-Type", "application/json");
            HttpRequest request;
            if ("POST".equals(method)) {
                request = builder.POST(HttpRequest.BodyPublishers.ofString(
                        jsonBody != null ? jsonBody : "", StandardCharsets.UTF_8)).build();
            } else {
                request = builder.GET().build();
            }
            return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
                    .send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        if (process != null) {
            process.destroy();
            try {
                if (!process.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        callbackServer.stop(0);
    }
}

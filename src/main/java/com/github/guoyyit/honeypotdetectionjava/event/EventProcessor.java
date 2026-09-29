package com.github.guoyyit.honeypotdetectionjava.event;

import com.github.guoyyit.honeypotdetectionjava.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyResource;
import com.github.guoyyit.honeypotdetectionjava.decoy.DecoyService;
import jakarta.annotation.PreDestroy;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import org.springframework.beans.factory.ObjectProvider;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

@Component
public class EventProcessor {

    private static final Logger log = LoggerFactory.getLogger(EventProcessor.class);

    private final ObjectProvider<TouchEventService> touchEventServiceProvider;
    private final AlertService alertService;
    private final DecoyService decoyService;

    private final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>();
    private final Object processingLock = new Object();
    private final Set<String> inFlight = new HashSet<>();
    private Thread worker;
    private volatile boolean running;

    public EventProcessor(ObjectProvider<TouchEventService> touchEventServiceProvider,
                          AlertService alertService, DecoyService decoyService) {
        this.touchEventServiceProvider = touchEventServiceProvider;
        this.alertService = alertService;
        this.decoyService = decoyService;
    }

    public synchronized void start() {
        running = true;
        worker = new Thread(this::runLoop, "honeypot-event-processor");
        worker.setDaemon(true);
        worker.start();
    }

    @EventListener(ApplicationReadyEvent.class)
    public synchronized void recoverAfterStartup() {
        if (!running) {
            start();
        }
        java.util.List<TouchEvent> recovered = touchEventServiceProvider.getObject().findUnprocessed();
        recovered.forEach(event -> queue.offer(event.getEventId()));
        log.info("Event processor started, {} unprocessed events recovered",
                recovered.size());
    }

    public void submit(String eventId) {
        if (running) {
            queue.offer(eventId);
        }
    }

    public void processPending() {
        for (TouchEvent event : touchEventServiceProvider.getObject().findUnprocessed()) {
            processOne(event.getEventId());
        }
    }

    @PreDestroy
    public void stop() {
        running = false;
        if (worker != null) {
            worker.interrupt();
            try {
                worker.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        processPending();
    }

    private void runLoop() {
        while (running) {
            try {
                String eventId = queue.poll(1, TimeUnit.SECONDS);
                if (eventId != null) {
                    processOne(eventId);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                log.error("Failed to process touch event", e);
            }
        }
    }

    private void processOne(String eventId) {
        synchronized (processingLock) {
            if (!inFlight.add(eventId)) {
                return;
            }
        }
        try {
            doProcess(eventId);
        } finally {
            synchronized (processingLock) {
                inFlight.remove(eventId);
            }
        }
    }

    private void doProcess(String eventId) {
        TouchEventService touchEventService = touchEventServiceProvider.getObject();
        TouchEvent event = touchEventService.listAll().stream()
                .filter(e -> eventId.equals(e.getEventId()))
                .findFirst()
                .orElse(null);
        if (event == null || event.isProcessed()) {
            return;
        }
        if (!event.isExempted()) {
            DecoyResource decoy = decoyService.get(event.getDecoyId());
            int sensitivity = decoy != null ? decoy.getSensitivity() : 0;
            alertService.processEvent(event, sensitivity);
        }
        touchEventService.markProcessed(eventId);
    }
}

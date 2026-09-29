package com.github.guoyyit.honeypotdetectionjava.honeypot.event;

import com.github.guoyyit.honeypotdetectionjava.honeypot.alert.AlertService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.TouchEventStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Drains persisted touch events and routes them to alerting.
 * Reloads unprocessed events on startup so nothing is lost across restarts.
 * Processing is idempotent: an event already marked processed is never handled twice.
 */
public class TouchEventProcessor {

    private static final Logger log = LoggerFactory.getLogger(TouchEventProcessor.class);

    private final TouchEventStore store;
    private final AlertService alertService;
    private final BlockingQueue<String> queue = new LinkedBlockingQueue<>();
    private volatile Thread worker;
    private volatile boolean running;

    public TouchEventProcessor(TouchEventStore store, AlertService alertService) {
        this.store = store;
        this.alertService = alertService;
    }

    public void start() {
        if (running) {
            return;
        }
        running = true;
        // Recover events persisted but not yet processed (e.g. before a restart).
        store.listPending().forEach(event -> queue.offer(event.id));
        worker = new Thread(this::drainLoop, "honeypot-touch-processor");
        worker.setDaemon(true);
        worker.start();
    }

    public void stop() {
        running = false;
        if (worker != null) {
            worker.interrupt();
            try {
                worker.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void enqueue(String eventId) {
        queue.offer(eventId);
    }

    /**
     * Waits until every persisted event has been processed. Intended for tests
     * and graceful shutdown verification.
     */
    public boolean awaitIdle(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (queue.isEmpty() && store.listPending().isEmpty()) {
                return true;
            }
            Thread.sleep(10);
        }
        return queue.isEmpty() && store.listPending().isEmpty();
    }

    private void drainLoop() {
        while (running || !queue.isEmpty()) {
            String eventId;
            try {
                eventId = queue.poll(200, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                if (!running) {
                    break;
                }
                continue;
            }
            if (eventId != null) {
                process(eventId);
            }
        }
    }

    private void process(String eventId) {
        try {
            if (store.isProcessed(eventId)) {
                return; // idempotent: never handle the same event twice
            }
            Optional<TouchEvent> found = store.findById(eventId);
            if (found.isEmpty()) {
                log.warn("Touch event {} not found in store, skipping", eventId);
                return;
            }
            alertService.handleTouch(found.get());
            store.markProcessed(eventId);
        } catch (Exception e) {
            // Leave the event unprocessed so it is retried after restart.
            log.error("Failed to process touch event {}", eventId, e);
        }
    }
}

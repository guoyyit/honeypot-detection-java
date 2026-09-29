package com.github.guoyyit.honeypotdetectionjava.honeypot.event;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyType;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.ExemptionRule;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.Sensitivity;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.honeypot.exemption.ExemptionService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.TouchEventStore;

import java.util.Optional;
import java.util.UUID;

/**
 * Records touch events durably and hands them to the processor. The event is
 * appended to the durable store before it is enqueued, so a restart never loses it.
 */
public class TouchEventService {

    private final TouchEventStore store;
    private final ExemptionService exemptionService;
    private final TouchEventProcessor processor;

    public TouchEventService(TouchEventStore store, ExemptionService exemptionService,
                             TouchEventProcessor processor) {
        this.store = store;
        this.exemptionService = exemptionService;
        this.processor = processor;
    }

    public TouchEvent recordTouch(DecoyType decoyType, String decoyId, Sensitivity sensitivity,
                                  String source, String path, String userAgent, String detail) {
        TouchEvent event = new TouchEvent();
        event.id = "evt-" + UUID.randomUUID();
        event.decoyType = decoyType;
        event.decoyId = decoyId;
        event.sensitivity = sensitivity;
        event.source = source;
        event.occurredAt = System.currentTimeMillis();
        event.detail = detail;

        Optional<ExemptionRule> exemption = exemptionService.match(source, path, userAgent);
        if (exemption.isPresent()) {
            event.exempted = true;
            event.exemptionRuleId = exemption.get().id;
        }

        store.append(event);
        processor.enqueue(event.id);
        return event;
    }
}

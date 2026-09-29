package com.github.guoyyit.honeypotdetectionjava.decoy;

import com.github.guoyyit.honeypotdetectionjava.event.TouchEvent;
import com.github.guoyyit.honeypotdetectionjava.event.TouchEventService;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionMatch;
import com.github.guoyyit.honeypotdetectionjava.exemption.ExemptionService;
import com.github.guoyyit.honeypotdetectionjava.web.AccessContext;
import org.springframework.stereotype.Service;

@Service
public class CredentialDetectionService {

    private final DecoyService decoyService;
    private final TouchEventService touchEventService;
    private final ExemptionService exemptionService;

    public CredentialDetectionService(DecoyService decoyService,
                                      TouchEventService touchEventService,
                                      ExemptionService exemptionService) {
        this.decoyService = decoyService;
        this.touchEventService = touchEventService;
        this.exemptionService = exemptionService;
    }

    public TouchEvent detect(String username, String rawPassword, AccessContext context,
                             String headerName, String headerValue) {
        DecoyResource decoy = decoyService.findEnabledCredential(username, rawPassword);
        if (decoy == null) {
            return null;
        }
        ExemptionMatch match = exemptionService.match(context.getSourceIp(), context.getPath(),
                context.getUserAgent(), headerName, headerValue);
        return touchEventService.record(decoy.getId(), TouchKind.CREDENTIAL,
                context.getSourceIp(), context.getUserAgent(), context.getPath(),
                match.isMatched(), match.getRuleId());
    }
}

package com.github.guoyyit.honeypotdetectionjava.honeypot.detection;

import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyCredential;
import com.github.guoyyit.honeypotdetectionjava.honeypot.domain.DecoyType;
import com.github.guoyyit.honeypotdetectionjava.honeypot.event.TouchEventService;
import com.github.guoyyit.honeypotdetectionjava.honeypot.store.DecoyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Detects decoy credentials during authentication. Runs as an O(1) lookup so the
 * normal authentication path is not slowed down, and never throws so it cannot
 * interfere with real user authentication.
 */
public class DecoyCredentialDetector {

    private static final Logger log = LoggerFactory.getLogger(DecoyCredentialDetector.class);

    private final DecoyRepository decoyRepository;
    private final TouchEventService touchEventService;

    public DecoyCredentialDetector(DecoyRepository decoyRepository, TouchEventService touchEventService) {
        this.decoyRepository = decoyRepository;
        this.touchEventService = touchEventService;
    }

    /**
     * Records a touch event if the username belongs to an enabled decoy credential,
     * regardless of whether the authentication itself succeeds or fails.
     */
    public void check(String username, String secret, String source) {
        try {
            Optional<DecoyCredential> decoy = decoyRepository.findCredentialByUsername(username);
            if (decoy.isEmpty()) {
                return;
            }
            DecoyCredential credential = decoy.get();
            boolean secretMatched = credential.secret != null && credential.secret.equals(secret);
            touchEventService.recordTouch(DecoyType.CREDENTIAL, credential.id, credential.sensitivity,
                    source, null, null,
                    "decoy credential '" + credential.username + "' used in login attempt"
                            + (secretMatched ? " (secret matched)" : " (secret mismatch)"));
        } catch (Exception e) {
            // Detection must never break the authentication path.
            log.error("Decoy credential detection failed", e);
        }
    }
}

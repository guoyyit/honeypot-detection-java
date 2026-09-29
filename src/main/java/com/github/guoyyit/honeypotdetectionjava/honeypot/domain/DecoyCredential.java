package com.github.guoyyit.honeypotdetectionjava.honeypot.domain;

/**
 * A decoy credential. Any authentication attempt using {@link #username} is an attack signal.
 */
public class DecoyCredential {
    public String id;
    public String username;
    public String secret;
    public DecoyStatus status = DecoyStatus.ENABLED;
    public Sensitivity sensitivity = Sensitivity.HIGH;
    public long createdAt;
    public long updatedAt;
}

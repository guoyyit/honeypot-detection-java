package com.github.guoyyit.honeypotdetectionjava.exemption;

public class ExemptionMatch {
    private final boolean matched;
    private final String ruleId;

    public ExemptionMatch(boolean matched, String ruleId) {
        this.matched = matched;
        this.ruleId = ruleId;
    }

    public static ExemptionMatch none() {
        return new ExemptionMatch(false, null);
    }

    public boolean isMatched() {
        return matched;
    }

    public String getRuleId() {
        return ruleId;
    }
}

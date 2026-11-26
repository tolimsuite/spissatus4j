package cn.tolim.spissatus4j.contract.policy;

import java.util.Map;
import java.util.Objects;

/**
 * Result of policy evaluation.
 *
 * <p>Merging is strictest-wins: DENY beats WARN beats ALLOW. A null decision
 * is converted to DENY (fail-closed) by {@link #strictest}.</p>
 *
 * @param outcome allow, warn or deny
 * @param reasonCode stable reason code from {@link ReasonCodes} or a custom code
 * @param message non-sensitive explanation safe for logs
 * @param policyId identifier of the deciding rule
 * @param details additional non-sensitive context
 */
public record PolicyDecision(Outcome outcome, String reasonCode, String message, String policyId,
                             Map<String, String> details) {

    public enum Outcome {
        ALLOW,
        WARN,
        DENY
    }

    public PolicyDecision {
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(reasonCode, "reasonCode");
        message = Objects.requireNonNull(message, "message");
        policyId = Objects.requireNonNull(policyId, "policyId");
        details = Map.copyOf(Objects.requireNonNull(details, "details"));
    }

    public static PolicyDecision allow(String policyId) {
        return new PolicyDecision(Outcome.ALLOW, "ALLOWED", "Allowed", policyId, Map.of());
    }

    public static PolicyDecision warn(String reasonCode, String message, String policyId) {
        return new PolicyDecision(Outcome.WARN, reasonCode, message, policyId, Map.of());
    }

    public static PolicyDecision deny(String reasonCode, String message, String policyId) {
        return new PolicyDecision(Outcome.DENY, reasonCode, message, policyId, Map.of());
    }

    public static PolicyDecision deny(String reasonCode, String message, String policyId,
                                      Map<String, String> details) {
        return new PolicyDecision(Outcome.DENY, reasonCode, message, policyId, details);
    }

    /** Merges two decisions, choosing the strictest. Null becomes a DENY. */
    public static PolicyDecision strictest(PolicyDecision left, PolicyDecision right) {
        if (left == null) {
            return right == null
                    ? deny(ReasonCodes.POLICY_UNAVAILABLE, "No policy decision available", "fail-closed")
                    : right;
        }
        if (right == null) {
            return left;
        }
        return severity(left.outcome()) >= severity(right.outcome()) ? left : right;
    }

    private static int severity(Outcome outcome) {
        return switch (outcome) {
            case ALLOW -> 0;
            case WARN -> 1;
            case DENY -> 2;
        };
    }

    public boolean denied() {
        return outcome == Outcome.DENY;
    }

    public boolean warned() {
        return outcome == Outcome.WARN;
    }

    public boolean allowed() {
        return outcome != Outcome.DENY;
    }
}
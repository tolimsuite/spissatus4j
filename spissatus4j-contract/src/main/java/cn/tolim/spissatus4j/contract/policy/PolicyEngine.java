package cn.tolim.spissatus4j.contract.policy;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;

/**
 * Unified decision point. Implementations combine all rules with
 * strictest-wins semantics and are fail-closed: an unavailable rule or source
 * yields DENY, never ALLOW.
 */
public interface PolicyEngine {

    String engineId();

    PolicyDecision evaluate(PolicyRequest request);

    /**
     * Non-authoritative selection hints. The crypto service still performs the
     * single authoritative {@link #evaluate(PolicyRequest)} call.
     */
    default SelectionHints selectionHints(CallerContext caller) {
        return SelectionHints.none();
    }

    HealthStatus health();

    default void refresh() {
    }
}
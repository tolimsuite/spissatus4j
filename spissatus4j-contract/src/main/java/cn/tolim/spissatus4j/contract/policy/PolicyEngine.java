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

    HealthStatus health();

    default void refresh() {
    }
}
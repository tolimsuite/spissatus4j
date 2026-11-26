package cn.tolim.spissatus4j.contract.policy;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;

/** Single composable policy rule. Implementations must not throw; deny instead. */
public interface PolicyRule {

    String ruleId();

    PolicyDecision evaluate(PolicyRequest request);

    default HealthStatus health() {
        return HealthStatus.UP;
    }
}
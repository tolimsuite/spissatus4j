package cn.tolim.spissatus4j.contract.compliance;

import cn.tolim.spissatus4j.contract.policy.PolicyRule;

/** Policy rule enforcing the configured {@link ComplianceMode}. */
public interface CompliancePolicy extends PolicyRule {

    ComplianceMode mode();
}
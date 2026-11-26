package cn.tolim.spissatus4j.policy.decision;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmCatalog;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.compliance.CompliancePolicy;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;

import java.util.Objects;

/**
 * Policy rule enforcing the configured {@link ComplianceMode}.
 *
 * <p>The algorithm is taken from the request, falling back to the key
 * descriptor's algorithm when the request itself does not name one. Requests
 * that reference no algorithm at all are outside this rule's scope and are
 * allowed.</p>
 */
public final class ComplianceRule implements CompliancePolicy {

    /** Stable, non-sensitive policy identifier. */
    public static final String RULE_ID = "compliance";

    private final ComplianceMode mode;

    /** Creates a rule in {@link ComplianceMode#STANDARD} mode. */
    public ComplianceRule() {
        this(ComplianceMode.STANDARD);
    }

    /**
     * Creates a rule for the supplied mode.
     *
     * @param mode compliance profile to enforce
     */
    public ComplianceRule(ComplianceMode mode) {
        this.mode = Objects.requireNonNull(mode, "mode");
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public ComplianceMode mode() {
        return mode;
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        if (request == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No policy request available", RULE_ID);
        }
        if (request.operation() == Operation.DESTROY_KEY
                || request.operation() == Operation.REVOKE_KEY
                || request.operation() == Operation.COMPROMISE_KEY
                || request.operation() == Operation.DEACTIVATE_KEY
                || request.operation() == Operation.READ_KEY) {
            return PolicyDecision.allow(RULE_ID);
        }
        AlgorithmId algorithm = request.algorithm();
        if (algorithm == null) {
            KeyDescriptor key = request.key();
            if (key == null) {
                return PolicyDecision.allow(RULE_ID);
            }
            algorithm = key.algorithm();
        }
        AlgorithmInfo info = AlgorithmCatalog.infoOrUnknown(algorithm.id());
        if (!mode.allows(info)) {
            return PolicyDecision.deny(ReasonCodes.COMPLIANCE_MODE_VIOLATION,
                    mode.violationReason(info), RULE_ID);
        }
        return PolicyDecision.allow(RULE_ID);
    }
}
package cn.tolim.spissatus4j.core.runtime;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import java.util.Objects;

/** Facade-level defence-in-depth check for the configured compliance mode. */
public final class ComplianceGuard {

    private ComplianceGuard() {
    }

    public static void enforce(ComplianceMode mode, AlgorithmInfo info) {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(info, "info");
        if (!mode.allows(info)) {
            throw new PolicyException(ErrorCode.COMPLIANCE_MODE_DENIED,
                    "Algorithm is not allowed by compliance mode " + mode + ": " + info.id().id());
        }
    }
}
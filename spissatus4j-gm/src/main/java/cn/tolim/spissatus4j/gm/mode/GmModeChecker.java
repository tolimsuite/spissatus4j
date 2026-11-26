package cn.tolim.spissatus4j.gm.mode;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import java.util.Objects;
import java.util.Set;

/**
 * Enforces the relationship between a compliance profile and GM algorithms.
 *
 * <ul>
 *   <li>{@code STANDARD}: the mode itself restricts nothing.</li>
 *   <li>{@code FIPS}: only FIPS-approved, non-GM algorithms.</li>
 *   <li>{@code GM}: only non-prohibited GM/T algorithms (SM2/SM3/SM4 ids).</li>
 *   <li>{@code GM_HYBRID}: GM/T plus catalog-approved non-GM algorithms.</li>
 * </ul>
 */
public final class GmModeChecker {

    private static final Set<AlgorithmId> GM_ALGORITHMS = Set.of(
            AlgorithmId.SM2,
            AlgorithmId.SM2_SIGNATURE,
            AlgorithmId.SM3,
            AlgorithmId.HMAC_SM3,
            AlgorithmId.SM4,
            AlgorithmId.SM4_ECB,
            AlgorithmId.SM4_GCM,
            AlgorithmId.SM4_CBC,
            AlgorithmId.SM4_CTR);

    private GmModeChecker() {
    }

    /** Returns whether the identifier belongs to the Chinese GM/T suite. */
    public static boolean isGmAlgorithm(AlgorithmId algorithm) {
        return algorithm != null && (GM_ALGORITHMS.contains(algorithm) || algorithm.info().gm());
    }

    /**
     * Returns whether the algorithm may be used under the given compliance
     * mode. Prohibited GM primitives (for example SM4-ECB) stay denied even in
     * GM modes; feed the result to the policy engine rather than treating it
     * as the only gate.
     */
    public static boolean allowedInMode(ComplianceMode mode, AlgorithmId algorithm) {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(algorithm, "algorithm");
        AlgorithmInfo info = algorithm.info();
        boolean gm = isGmAlgorithm(algorithm);
        return switch (mode) {
            case STANDARD -> true;
            case FIPS -> !gm && info.fipsApproved();
            case GM -> gm && !info.prohibited();
            case GM_HYBRID -> gm
                    ? !info.prohibited()
                    : algorithm.isKnown() && !info.prohibited();
        };
    }

    /** Requires a GM-capable compliance mode, otherwise denies with policy. */
    public static void requireGmOrHybrid(ComplianceMode mode) {
        Objects.requireNonNull(mode, "mode");
        if (mode != ComplianceMode.GM && mode != ComplianceMode.GM_HYBRID) {
            throw new PolicyException(ErrorCode.COMPLIANCE_MODE_DENIED,
                    "GM algorithms require GM or GM_HYBRID compliance mode");
        }
    }
}
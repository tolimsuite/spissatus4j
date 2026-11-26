package cn.tolim.spissatus4j.contract.compliance;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;

/**
 * Operating compliance profile.
 *
 * <ul>
 *   <li>{@code STANDARD}: all catalog algorithms, subject to policy.</li>
 *   <li>{@code FIPS}: only FIPS-approved algorithms.</li>
 *   <li>{@code GM}: only Chinese GM/T algorithms (SM2/SM3/SM4).</li>
 *   <li>{@code GM_HYBRID}: GM and standard algorithms side by side.</li>
 * </ul>
 */
public enum ComplianceMode {
    STANDARD,
    FIPS,
    GM,
    GM_HYBRID;

    public boolean allows(AlgorithmInfo info) {
        return switch (this) {
            case STANDARD, GM_HYBRID -> true;
            case FIPS -> info.fipsApproved();
            case GM -> info.gm();
        };
    }

    public String violationReason(AlgorithmInfo info) {
        return switch (this) {
            case FIPS -> info.displayName() + " is not FIPS-approved";
            case GM -> info.displayName() + " is not part of the GM/T suite";
            default -> info.displayName() + " is not allowed by compliance mode " + this;
        };
    }
}
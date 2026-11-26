package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import java.util.ArrayList;
import java.util.List;

/**
 * Named selection profile for the unified entry point. A profile is a static
 * preference table, never a cryptographic composition.
 */
public enum SelectionProfile {
    AUTO_AEAD,
    AUTO_AEAD_THEN_ETM,
    FIPS_AEAD,
    GM_AEAD,
    GM_HYBRID_AEAD;

    public static SelectionProfile defaultFor(ComplianceMode mode) {
        return switch (mode) {
            case STANDARD -> AUTO_AEAD;
            case FIPS -> FIPS_AEAD;
            case GM -> GM_AEAD;
            case GM_HYBRID -> GM_HYBRID_AEAD;
        };
    }

    public boolean allowedIn(ComplianceMode mode) {
        return switch (this) {
            case AUTO_AEAD, AUTO_AEAD_THEN_ETM -> true;
            case FIPS_AEAD -> mode == ComplianceMode.FIPS;
            case GM_AEAD -> mode == ComplianceMode.GM || mode == ComplianceMode.GM_HYBRID;
            case GM_HYBRID_AEAD -> mode == ComplianceMode.GM_HYBRID;
        };
    }

    /**
     * Static default preference order. The selector still applies all hard
     * filters; this list only defines deterministic ordering.
     */
    public List<AlgorithmId> defaultOrder(ComplianceMode mode) {
        List<AlgorithmId> base = switch (this) {
            case AUTO_AEAD, AUTO_AEAD_THEN_ETM -> switch (mode) {
                case STANDARD -> List.of(AlgorithmId.AES_GCM, AlgorithmId.CHACHA20_POLY1305);
                case FIPS -> List.of(AlgorithmId.AES_GCM);
                case GM -> List.of(AlgorithmId.SM4_GCM);
                case GM_HYBRID -> List.of(AlgorithmId.SM4_GCM, AlgorithmId.AES_GCM,
                        AlgorithmId.CHACHA20_POLY1305);
            };
            case FIPS_AEAD -> List.of(AlgorithmId.AES_GCM);
            case GM_AEAD -> List.of(AlgorithmId.SM4_GCM);
            case GM_HYBRID_AEAD -> List.of(AlgorithmId.SM4_GCM, AlgorithmId.AES_GCM,
                    AlgorithmId.CHACHA20_POLY1305);
        };
        if (this != AUTO_AEAD_THEN_ETM) {
            return base;
        }
        List<AlgorithmId> extended = new ArrayList<>(base);
        extended.addAll(List.of(AlgorithmId.AES_CTR, AlgorithmId.AES_CBC,
                AlgorithmId.AES_CFB, AlgorithmId.AES_OFB,
                AlgorithmId.SM4_CTR, AlgorithmId.SM4_CBC));
        return List.copyOf(extended);
    }
}
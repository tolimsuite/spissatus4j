package cn.tolim.spissatus4j.gm.compliance;

import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.util.Objects;

/**
 * Small, immutable compliance configuration for the GM module.
 *
 * <p>The GM module is usable in STANDARD, GM and GM_HYBRID profiles; a FIPS
 * profile cannot host the GM suite and is rejected at configuration time.</p>
 */
public record GmComplianceConfig(ComplianceMode mode) {

    public GmComplianceConfig {
        Objects.requireNonNull(mode, "mode");
    }

    public static GmComplianceConfig of(ComplianceMode mode) {
        return new GmComplianceConfig(mode);
    }

    /** Returns whether GM algorithms are admissible under this profile. */
    public boolean gmAlgorithmsAllowed() {
        return mode != ComplianceMode.FIPS;
    }

    /** Validates that the profile may host the GM module. */
    public void validateConfiguration() {
        if (mode == ComplianceMode.FIPS) {
            throw new ConfigurationException(ErrorCode.COMPLIANCE_VIOLATION,
                    "GM module cannot be configured in FIPS mode");
        }
    }
}
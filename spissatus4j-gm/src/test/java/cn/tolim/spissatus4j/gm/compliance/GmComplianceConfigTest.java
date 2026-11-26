package cn.tolim.spissatus4j.gm.compliance;

import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GmComplianceConfigTest {

    @Test
    void nonFipsProfilesValidate() {
        for (ComplianceMode mode : new ComplianceMode[] {
                ComplianceMode.STANDARD, ComplianceMode.GM, ComplianceMode.GM_HYBRID}) {
            GmComplianceConfig config = GmComplianceConfig.of(mode);
            assertDoesNotThrow(config::validateConfiguration);
            assertTrue(config.gmAlgorithmsAllowed());
            assertEquals(mode, config.mode());
        }
    }

    @Test
    void fipsProfileIsRejected() {
        GmComplianceConfig config = new GmComplianceConfig(ComplianceMode.FIPS);
        ConfigurationException exception =
                assertThrows(ConfigurationException.class, config::validateConfiguration);
        assertEquals(ErrorCode.COMPLIANCE_VIOLATION, exception.errorCode());
        assertFalse(config.gmAlgorithmsAllowed());
    }

    @Test
    void recordEqualityFollowsMode() {
        assertEquals(GmComplianceConfig.of(ComplianceMode.GM),
                GmComplianceConfig.of(ComplianceMode.GM));
        assertFalse(GmComplianceConfig.of(ComplianceMode.GM)
                .equals(GmComplianceConfig.of(ComplianceMode.GM_HYBRID)));
    }

    @Test
    void nullModeIsRejected() {
        assertThrows(NullPointerException.class, () -> new GmComplianceConfig(null));
    }
}
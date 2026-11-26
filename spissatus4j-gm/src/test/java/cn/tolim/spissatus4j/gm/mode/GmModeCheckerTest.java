package cn.tolim.spissatus4j.gm.mode;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GmModeCheckerTest {

    private static final AlgorithmId UNKNOWN = AlgorithmId.of("VENDOR-CUSTOM");

    @Test
    void recognizesGmAlgorithms() {
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.SM2));
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.SM2_SIGNATURE));
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.SM3));
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.HMAC_SM3));
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.SM4_GCM));
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.SM4_CBC));
        assertTrue(GmModeChecker.isGmAlgorithm(AlgorithmId.SM4_CTR));
    }

    @Test
    void rejectsNonGmAndUnknownAlgorithms() {
        assertFalse(GmModeChecker.isGmAlgorithm(AlgorithmId.AES_GCM));
        assertFalse(GmModeChecker.isGmAlgorithm(AlgorithmId.SHA_256));
        assertFalse(GmModeChecker.isGmAlgorithm(AlgorithmId.ECDSA_P256));
        assertFalse(GmModeChecker.isGmAlgorithm(UNKNOWN));
        assertFalse(GmModeChecker.isGmAlgorithm(null));
    }

    @Test
    void standardModeRestrictsNothing() {
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.STANDARD, AlgorithmId.AES_GCM));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.STANDARD, AlgorithmId.SM4_GCM));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.STANDARD, AlgorithmId.MD5));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.STANDARD, UNKNOWN));
    }

    @Test
    void fipsModeRejectsGmAlgorithms() {
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.FIPS, AlgorithmId.SM2));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.FIPS, AlgorithmId.SM3));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.FIPS, AlgorithmId.SM4_GCM));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.FIPS, AlgorithmId.SHA_256));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.FIPS, AlgorithmId.AES_GCM));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.FIPS, UNKNOWN));
    }

    @Test
    void gmModeAcceptsOnlyGmAlgorithms() {
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM2));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM3));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.HMAC_SM3));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM4_GCM));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM4_CBC));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM4_CTR));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.AES_GCM));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SHA_256));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM, UNKNOWN));
    }

    @Test
    void gmHybridModeAcceptsGmPlusCatalogApprovedNonGm() {
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.SM2));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.SM4_GCM));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.AES_GCM));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.SHA_256));
        assertTrue(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.ECDSA_P256));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.MD5));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, UNKNOWN));
    }

    @Test
    void prohibitedGmPrimitivesRemainDeniedInGmModes() {
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM4_ECB));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM, AlgorithmId.SM4));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.SM4_ECB));
        assertFalse(GmModeChecker.allowedInMode(ComplianceMode.GM_HYBRID, AlgorithmId.SM4));
    }

    @Test
    void requireGmOrHybridAcceptsGmProfiles() {
        assertDoesNotThrow(() -> GmModeChecker.requireGmOrHybrid(ComplianceMode.GM));
        assertDoesNotThrow(() -> GmModeChecker.requireGmOrHybrid(ComplianceMode.GM_HYBRID));
    }

    @Test
    void requireGmOrHybridDeniesOtherProfiles() {
        for (ComplianceMode mode : new ComplianceMode[] {ComplianceMode.STANDARD, ComplianceMode.FIPS}) {
            PolicyException exception = assertThrows(PolicyException.class,
                    () -> GmModeChecker.requireGmOrHybrid(mode));
            assertEquals(ErrorCode.COMPLIANCE_MODE_DENIED, exception.errorCode());
        }
    }
}
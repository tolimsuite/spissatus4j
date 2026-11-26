package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.policy.decision.ComplianceRule;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ComplianceRuleTest {

    @Test
    void standardModeAllowsAllCatalogAlgorithms() {
        ComplianceRule rule = new ComplianceRule();

        assertEquals(ComplianceMode.STANDARD, rule.mode());
        assertTrue(rule.evaluate(request(AlgorithmId.AES_GCM)).allowed());
        assertTrue(rule.evaluate(request(AlgorithmId.CHACHA20_POLY1305)).allowed());
        assertEquals("compliance", rule.ruleId());
    }

    @Test
    void fipsModeDeniesNonFipsAlgorithm() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.FIPS);

        PolicyDecision decision = rule.evaluate(request(AlgorithmId.CHACHA20_POLY1305));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.COMPLIANCE_MODE_VIOLATION, decision.reasonCode());
        assertTrue(decision.message().contains("not FIPS-approved"));
    }

    @Test
    void fipsModeAllowsFipsAlgorithm() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.FIPS);

        assertTrue(rule.evaluate(request(AlgorithmId.AES_GCM)).allowed());
        assertTrue(rule.evaluate(request(AlgorithmId.SHA_256)).allowed());
    }

    @Test
    void gmModeDeniesStandardAlgorithm() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.GM);

        PolicyDecision decision = rule.evaluate(request(AlgorithmId.AES_GCM));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.COMPLIANCE_MODE_VIOLATION, decision.reasonCode());
    }

    @Test
    void gmModeAllowsSm4Gcm() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.GM);

        assertTrue(rule.evaluate(request(AlgorithmId.SM4_GCM)).allowed());
    }

    @Test
    void gmHybridModeAllowsBothSuites() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.GM_HYBRID);

        assertTrue(rule.evaluate(request(AlgorithmId.AES_GCM)).allowed());
        assertTrue(rule.evaluate(request(AlgorithmId.SM4_GCM)).allowed());
        assertTrue(rule.evaluate(request(AlgorithmId.CHACHA20_POLY1305)).allowed());
    }

    @Test
    void gmModeDeniesChaCha20() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.GM);

        assertTrue(rule.evaluate(request(AlgorithmId.CHACHA20_POLY1305)).denied());
    }

    @Test
    void requestWithoutAlgorithmIsOutOfScope() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.FIPS);

        assertTrue(rule.evaluate(PolicyRequest.of(Operation.GENERATE_KEY, TestFixtures.caller())).allowed());
    }

    @Test
    void descriptorAlgorithmIsUsedWhenRequestHasNone() {
        ComplianceRule rule = new ComplianceRule(ComplianceMode.GM);
        PolicyRequest request = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .key(TestFixtures.key(cn.tolim.spissatus4j.contract.key.KeyState.ACTIVE,
                        java.util.Set.of(cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 128, AlgorithmId.AES_GCM, null))
                .build();

        assertTrue(rule.evaluate(request).denied());
    }

    private static PolicyRequest request(AlgorithmId algorithm) {
        return PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .algorithm(algorithm)
                .build();
    }
}
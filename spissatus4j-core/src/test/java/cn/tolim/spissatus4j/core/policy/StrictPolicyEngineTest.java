package cn.tolim.spissatus4j.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class StrictPolicyEngineTest {

    private static final CallerContext CALLER =
            CallerContext.of("tester", "tenant-a", Set.of("crypto-user"));

    private static KeyDescriptor descriptor(AlgorithmId algorithm, KeyType type, int bits,
                                            KeyState state, Set<KeyUsage> usages, String tenant) {
        return KeyDescriptor.builder()
                .keyId(KeyId.of("policy-key"))
                .version(KeyVersion.first())
                .type(type)
                .algorithm(algorithm)
                .keyBits(bits)
                .state(state)
                .usages(usages)
                .tenantId(tenant)
                .createdAt(Instant.now())
                .activatedAt(Instant.now())
                .build();
    }

    private static PolicyRequest request(Operation operation, AlgorithmId algorithm, KeyDescriptor key,
                                         CallerContext caller) {
        return PolicyRequest.builder(operation, caller)
                .algorithm(algorithm)
                .key(key)
                .keyId(key == null ? null : key.keyId())
                .build();
    }

    @Test
    void allowsRecommendedAlgorithmForActiveKey() {
        var engine = new StrictPolicyEngine();
        var key = descriptor(AlgorithmId.AES_GCM, KeyType.AES, 256, KeyState.ACTIVE,
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), "tenant-a");
        PolicyDecision decision = engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM,
                key, CALLER));
        assertTrue(decision.allowed());
        assertEquals(PolicyDecision.Outcome.ALLOW, decision.outcome());
    }

    @Test
    void deniesProhibitedAlgorithms() {
        var engine = new StrictPolicyEngine();
        PolicyDecision decision = engine.evaluate(PolicyRequest.builder(Operation.DIGEST, CALLER)
                .algorithm(AlgorithmId.MD5).build());
        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, decision.reasonCode());
    }

    @Test
    void warnsOnDeprecatedAlgorithms() {
        var engine = new StrictPolicyEngine();
        PolicyDecision decision = engine.evaluate(PolicyRequest.builder(Operation.ENCRYPT, CALLER)
                .algorithm(AlgorithmId.DES_EDE3_CBC).build());
        assertEquals(PolicyDecision.Outcome.WARN, decision.outcome());
        assertEquals(ReasonCodes.ALGORITHM_DEPRECATED, decision.reasonCode());
    }

    @Test
    void deniesExperimentalPostQuantumByDefault() {
        var engine = new StrictPolicyEngine();
        PolicyDecision decision = engine.evaluate(PolicyRequest.builder(Operation.GENERATE_KEY, CALLER)
                .algorithm(AlgorithmId.ML_KEM_768).build());
        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_EXPERIMENTAL, decision.reasonCode());
    }

    @Test
    void lifecycleCleanupRemainsPossibleForNonCompliantKeys() {
        var engine = new StrictPolicyEngine(ComplianceMode.FIPS);
        var key = descriptor(AlgorithmId.MD5, KeyType.RAW, 128, KeyState.ACTIVE,
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), "tenant-a");
        assertTrue(engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.MD5, key, CALLER))
                .denied());
        assertTrue(engine.evaluate(request(Operation.DESTROY_KEY, AlgorithmId.MD5, key, CALLER))
                .allowed());
        assertTrue(engine.evaluate(request(Operation.REVOKE_KEY, AlgorithmId.MD5, key, CALLER))
                .allowed());
    }

    @Test
    void deniesUndersizedKeys() {
        var engine = new StrictPolicyEngine();
        var key = descriptor(AlgorithmId.RSA_OAEP, KeyType.RSA, 1024, KeyState.ACTIVE,
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), "tenant-a");
        PolicyDecision decision = engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.RSA_OAEP,
                key, CALLER));
        assertTrue(decision.denied());
        assertEquals(ReasonCodes.MIN_KEY_BITS, decision.reasonCode());
    }

    @Test
    void enforcesUsageAndStateIsolation() {
        var engine = new StrictPolicyEngine();
        var signOnly = descriptor(AlgorithmId.ED25519, KeyType.ED25519, 256, KeyState.ACTIVE,
                Set.of(KeyUsage.SIGN, KeyUsage.VERIFY), "tenant-a");
        PolicyDecision usage = engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.ED25519,
                signOnly, CALLER));
        assertTrue(usage.denied());
        var deactivated = descriptor(AlgorithmId.AES_GCM, KeyType.AES, 256, KeyState.DEACTIVATED,
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), "tenant-a");
        assertTrue(engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM, deactivated, CALLER))
                .denied());
        assertTrue(engine.evaluate(request(Operation.DECRYPT, AlgorithmId.AES_GCM, deactivated, CALLER))
                .allowed());
    }

    @Test
    void deniesAnonymousAndCrossTenantAccess() {
        var engine = new StrictPolicyEngine();
        assertTrue(engine.evaluate(request(Operation.DIGEST, AlgorithmId.SHA_256, null,
                CallerContext.anonymous())).denied());
        var key = descriptor(AlgorithmId.AES_GCM, KeyType.AES, 256, KeyState.ACTIVE,
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), "tenant-b");
        assertTrue(engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM, key, CALLER))
                .denied());
        CallerContext crossTenant = CallerContext.of("admin", "tenant-a",
                Set.of("crypto-cross-tenant"));
        assertTrue(engine.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM, key, crossTenant))
                .allowed());
    }

    @Test
    void enforcesComplianceMode() {
        var fips = new StrictPolicyEngine(ComplianceMode.FIPS);
        assertTrue(fips.evaluate(PolicyRequest.builder(Operation.ENCRYPT, CALLER)
                .algorithm(AlgorithmId.CHACHA20_POLY1305).build()).denied());
        var gm = new StrictPolicyEngine(ComplianceMode.GM);
        assertTrue(gm.evaluate(PolicyRequest.builder(Operation.ENCRYPT, CALLER)
                .algorithm(AlgorithmId.AES_GCM).build()).denied());
        assertTrue(gm.evaluate(PolicyRequest.builder(Operation.ENCRYPT, CALLER)
                .algorithm(AlgorithmId.SM4_GCM).build()).allowed());
        var hybrid = new StrictPolicyEngine(ComplianceMode.GM_HYBRID);
        assertTrue(hybrid.evaluate(PolicyRequest.builder(Operation.ENCRYPT, CALLER)
                .algorithm(AlgorithmId.AES_GCM).build()).allowed());
    }

    @Test
    void unknownAlgorithmIsDenied() {
        var engine = new StrictPolicyEngine();
        PolicyDecision decision = engine.evaluate(PolicyRequest.builder(Operation.ENCRYPT, CALLER)
                .algorithm(AlgorithmId.of("CUSTOM-UNKNOWN")).build());
        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_UNKNOWN, decision.reasonCode());
    }
}
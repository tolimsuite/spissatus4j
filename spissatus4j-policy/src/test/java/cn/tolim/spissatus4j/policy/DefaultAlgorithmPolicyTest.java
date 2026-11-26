package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.policy.algorithm.DefaultAlgorithmPolicy;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultAlgorithmPolicyTest {

    private final DefaultAlgorithmPolicy policy = new DefaultAlgorithmPolicy();

    @Test
    void allowsAesGcmForDefaultPolicy() {
        PolicyDecision decision = policy.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM));

        assertEquals(PolicyDecision.Outcome.ALLOW, decision.outcome());
        assertEquals("algorithm", decision.policyId());
        assertTrue(decision.allowed());
    }

    @Test
    void deniesMd5AndSha1AsProhibited() {
        PolicyDecision md5 = policy.evaluate(request(Operation.DIGEST, AlgorithmId.MD5));
        PolicyDecision sha1 = policy.evaluate(request(Operation.DIGEST, AlgorithmId.SHA_1));

        assertTrue(md5.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, md5.reasonCode());
        assertTrue(sha1.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, sha1.reasonCode());
    }

    @Test
    void deniesAesEcbAsProhibited() {
        PolicyDecision decision = policy.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_ECB));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, decision.reasonCode());
    }

    @Test
    void deniesUnknownAlgorithm() {
        PolicyDecision decision = policy.evaluate(request(Operation.ENCRYPT,
                AlgorithmId.of("CUSTOM-UNREGISTERED-ALG")));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_UNKNOWN, decision.reasonCode());
    }

    @Test
    void allowsRequestWithoutAlgorithm() {
        PolicyRequest request = PolicyRequest.of(Operation.GENERATE_KEY, TestFixtures.caller());

        assertTrue(policy.evaluate(request).allowed());
    }

    @Test
    void usesKeyDescriptorAlgorithmWhenRequestAlgorithmIsAbsent() {
        PolicyRequest aes = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 256, AlgorithmId.AES_GCM, null))
                .build();

        PolicyDecision decision = policy.evaluate(aes);

        assertTrue(decision.allowed(), "a known descriptor algorithm is evaluated normally");
        assertEquals(PolicyDecision.Outcome.ALLOW, decision.outcome());
    }

    @Test
    void deniesProhibitedAlgorithmFromKeyDescriptor() {
        PolicyRequest md5 = PolicyRequest.builder(Operation.MAC, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.MAC),
                        TestFixtures.TENANT, 128, AlgorithmId.MD5, null))
                .build();

        PolicyDecision decision = policy.evaluate(md5);

        assertTrue(decision.denied(), "a prohibited descriptor algorithm must not slip through");
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, decision.reasonCode());
    }

    @Test
    void appliesWhitelistExperimentalAndDeprecatedGatesToKeyDescriptorAlgorithm() {
        DefaultAlgorithmPolicy whitelisted = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM), Set.of(), false);
        PolicyRequest sha256 = PolicyRequest.builder(Operation.DIGEST, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.MAC),
                        TestFixtures.TENANT, 256, AlgorithmId.SHA_256, null))
                .build();
        PolicyDecision notAllowed = whitelisted.evaluate(sha256);
        assertTrue(notAllowed.denied());
        assertEquals(ReasonCodes.ALGORITHM_NOT_ALLOWED, notAllowed.reasonCode());

        PolicyRequest mlKem = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 768, AlgorithmId.ML_KEM_768, null))
                .build();
        PolicyDecision experimental = policy.evaluate(mlKem);
        assertTrue(experimental.denied());
        assertEquals(ReasonCodes.ALGORITHM_EXPERIMENTAL, experimental.reasonCode());

        PolicyRequest tripleDes = PolicyRequest.builder(Operation.DECRYPT, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.DECRYPT),
                        TestFixtures.TENANT, 168, AlgorithmId.DES_EDE3_CBC, null))
                .build();
        PolicyDecision deprecated = policy.evaluate(tripleDes);
        assertEquals(PolicyDecision.Outcome.WARN, deprecated.outcome());
        assertEquals(ReasonCodes.ALGORITHM_DEPRECATED, deprecated.reasonCode());
    }

    @Test
    void enforcesMinimumKeyBitsForKeyDescriptorAlgorithm() {
        PolicyRequest undersized = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 64, AlgorithmId.AES_GCM, null))
                .build();

        PolicyDecision decision = policy.evaluate(undersized);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.MIN_KEY_BITS, decision.reasonCode());
        assertEquals("128", decision.details().get("requiredBits"));
        assertEquals("64", decision.details().get("actualBits"));
    }

    @Test
    void warnsAboutDeprecated3Des() {
        PolicyDecision decision = policy.evaluate(request(Operation.DECRYPT, AlgorithmId.DES_EDE3_CBC));

        assertEquals(PolicyDecision.Outcome.WARN, decision.outcome());
        assertEquals(ReasonCodes.ALGORITHM_DEPRECATED, decision.reasonCode());
        assertTrue(decision.allowed());
        assertTrue(decision.warned());
    }

    @Test
    void deniesExperimentalMlKemUnlessExplicitlyAllowed() {
        PolicyDecision denied = policy.evaluate(request(Operation.ENCRYPT, AlgorithmId.ML_KEM_768));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.ALGORITHM_EXPERIMENTAL, denied.reasonCode());

        DefaultAlgorithmPolicy permissive = new DefaultAlgorithmPolicy(Set.of(), Set.of(), true);
        PolicyDecision allowed = permissive.evaluate(request(Operation.ENCRYPT, AlgorithmId.ML_KEM_768));
        assertTrue(allowed.allowed());
        assertFalse(allowed.denied());
    }

    @Test
    void deniesExplicitlyBlacklistedAlgorithm() {
        DefaultAlgorithmPolicy withBlacklist = new DefaultAlgorithmPolicy(
                Set.of(), Set.of(AlgorithmId.AES_GCM), false);

        PolicyDecision decision = withBlacklist.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, decision.reasonCode());
        assertEquals(Set.of(AlgorithmId.AES_GCM), withBlacklist.deniedAlgorithms());
    }

    @Test
    void whitelistAllowsOnlyListedAlgorithms() {
        DefaultAlgorithmPolicy withWhitelist = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM), Set.of(), false);

        assertTrue(withWhitelist.evaluate(request(Operation.ENCRYPT, AlgorithmId.AES_GCM)).allowed());

        PolicyDecision decision = withWhitelist.evaluate(request(Operation.DIGEST, AlgorithmId.SHA_256));
        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_NOT_ALLOWED, decision.reasonCode());
        assertEquals(Set.of(AlgorithmId.AES_GCM), withWhitelist.allowedAlgorithms());
    }

    @Test
    void deniesKeyBelowCatalogMinimumSize() {
        PolicyRequest request = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .algorithm(AlgorithmId.RSA_OAEP)
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 1024, AlgorithmId.RSA_OAEP, null))
                .build();

        PolicyDecision decision = policy.evaluate(request);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.MIN_KEY_BITS, decision.reasonCode());
        assertEquals("2048", decision.details().get("requiredBits"));
        assertEquals("1024", decision.details().get("actualBits"));
    }

    @Test
    void allowsKeyAtCatalogMinimumSize() {
        PolicyRequest request = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .algorithm(AlgorithmId.RSA_OAEP)
                .key(TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 2048, AlgorithmId.RSA_OAEP, null))
                .build();

        assertTrue(policy.evaluate(request).allowed());
    }

    @Test
    void skipsKeySizeCheckForGenerateKeyWithoutDescriptor() {
        PolicyRequest request = PolicyRequest.builder(Operation.GENERATE_KEY, TestFixtures.caller())
                .algorithm(AlgorithmId.RSA_OAEP)
                .build();

        assertTrue(policy.evaluate(request).allowed());
    }

    @Test
    void minimumKeyBitsUsesCatalogAndOverrides() {
        assertEquals(2048, policy.minimumKeyBits(AlgorithmId.RSA_OAEP));
        assertEquals(128, policy.minimumKeyBits(AlgorithmId.AES_GCM));
        assertEquals(0, policy.minimumKeyBits(null));

        DefaultAlgorithmPolicy overridden = new DefaultAlgorithmPolicy(Set.of(), Set.of(), false,
                Map.of(AlgorithmId.AES_GCM, 256));
        assertEquals(256, overridden.minimumKeyBits(AlgorithmId.AES_GCM));
        assertEquals(2048, overridden.minimumKeyBits(AlgorithmId.RSA_OAEP));
    }

    @Test
    void ruleIdIsStable() {
        assertEquals("algorithm", policy.ruleId());
    }

    private static PolicyRequest request(Operation operation, AlgorithmId algorithm) {
        return PolicyRequest.builder(operation, TestFixtures.caller()).algorithm(algorithm).build();
    }
    @Test
    void lifecycleCleanupIsAllowedForProhibitedKeys() {
        DefaultAlgorithmPolicy policy = new DefaultAlgorithmPolicy();
        cn.tolim.spissatus4j.contract.key.KeyDescriptor key =
                TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                        TestFixtures.TENANT, 128, AlgorithmId.MD5, null);
        assertTrue(policy.evaluate(PolicyRequest.builder(Operation.DESTROY_KEY,
                        TestFixtures.caller())
                .algorithm(AlgorithmId.MD5).key(key).build()).allowed());
        assertTrue(policy.evaluate(PolicyRequest.builder(Operation.REVOKE_KEY,
                        TestFixtures.caller())
                .algorithm(AlgorithmId.MD5).key(key).build()).allowed());
        assertTrue(policy.evaluate(PolicyRequest.builder(Operation.ENCRYPT,
                        TestFixtures.caller())
                .algorithm(AlgorithmId.MD5).key(key).build()).denied());
    }

}
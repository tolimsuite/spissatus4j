package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.policy.usage.DefaultUsagePolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class DefaultUsagePolicyTest {

    private final DefaultUsagePolicy policy = new DefaultUsagePolicy(
            Clock.fixed(TestFixtures.NOW, ZoneOffset.UTC));

    @Test
    void allowsRequestWithoutKeyDescriptor() {
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, TestFixtures.caller())).allowed());
    }

    @Test
    void allowsEncryptWithEncryptUsage() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT));

        assertTrue(policy.evaluate(request(Operation.ENCRYPT, key)).allowed());
    }

    @Test
    void deniesEncryptWhenKeyOnlySigns() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.SIGN));

        PolicyDecision decision = policy.evaluate(request(Operation.ENCRYPT, key));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.KEY_USAGE_MISMATCH, decision.reasonCode());
        assertEquals("usage", decision.policyId());
    }

    @Test
    void deactivatedKeyCannotProtectNewData() {
        KeyDescriptor key = TestFixtures.key(KeyState.DEACTIVATED, Set.of(KeyUsage.ENCRYPT));

        PolicyDecision decision = policy.evaluate(request(Operation.ENCRYPT, key));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.KEY_NOT_ACTIVE, decision.reasonCode());
    }

    @Test
    void deactivatedKeyCanProtectOnlyWithTheExplicitOptIn() {
        KeyDescriptor key = TestFixtures.key(KeyState.DEACTIVATED, Set.of(KeyUsage.ENCRYPT));

        PolicyRequest optedIn = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .key(key).allowDeactivatedEncryption(true).build();
        assertTrue(policy.evaluate(optedIn).allowed());

        PolicyRequest otherUsage = PolicyRequest.builder(Operation.SIGN, TestFixtures.caller())
                .key(TestFixtures.key(KeyState.DEACTIVATED, Set.of(KeyUsage.SIGN)))
                .allowDeactivatedEncryption(true).build();
        assertEquals(ReasonCodes.KEY_NOT_ACTIVE, policy.evaluate(otherUsage).reasonCode());
    }

    @Test
    void deactivatedKeyCanProcessHistoricalData() {
        KeyDescriptor key = TestFixtures.key(KeyState.DEACTIVATED, Set.of(KeyUsage.DECRYPT));

        assertTrue(policy.evaluate(request(Operation.DECRYPT, key)).allowed());
    }

    @Test
    void revokedKeyCannotProcessHistoricalData() {
        KeyDescriptor key = TestFixtures.key(KeyState.REVOKED, Set.of(KeyUsage.DECRYPT));

        PolicyDecision decision = policy.evaluate(request(Operation.DECRYPT, key));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.KEY_NOT_ACTIVE, decision.reasonCode());
    }

    @Test
    void expiredKeyIsDenied() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                TestFixtures.TENANT, 256, cn.tolim.spissatus4j.contract.algorithm.AlgorithmId.AES_GCM,
                TestFixtures.NOW);

        PolicyDecision decision = policy.evaluate(request(Operation.ENCRYPT, key));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.KEY_EXPIRED, decision.reasonCode());
    }

    @Test
    void activeUnexpiredKeyIsAllowed() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT));

        assertTrue(policy.evaluate(request(Operation.ENCRYPT, key)).allowed());
    }

    @Test
    void lifecycleOperationNeedsNoKeyUsage() {
        KeyDescriptor key = TestFixtures.key(KeyState.DEACTIVATED, Set.of(KeyUsage.ENCRYPT));

        assertTrue(policy.evaluate(request(Operation.READ_KEY, key)).allowed());
        assertTrue(policy.evaluate(request(Operation.DEACTIVATE_KEY, key)).allowed());
    }

    @ParameterizedTest
    @MethodSource("usageMappings")
    void mapsOperationToRequiredUsage(Operation operation, KeyUsage usage) {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(usage));

        PolicyDecision decision = policy.evaluate(request(operation, key));

        assertTrue(decision.allowed(), () -> operation + " should be allowed with usage " + usage);
    }

    static Stream<Arguments> usageMappings() {
        return Stream.of(
                arguments(Operation.ENCRYPT, KeyUsage.ENCRYPT),
                arguments(Operation.STREAM_ENCRYPT, KeyUsage.ENCRYPT),
                arguments(Operation.DECRYPT, KeyUsage.DECRYPT),
                arguments(Operation.STREAM_DECRYPT, KeyUsage.DECRYPT),
                arguments(Operation.SIGN, KeyUsage.SIGN),
                arguments(Operation.VERIFY, KeyUsage.VERIFY),
                arguments(Operation.MAC, KeyUsage.MAC),
                arguments(Operation.VERIFY_MAC, KeyUsage.MAC),
                arguments(Operation.WRAP, KeyUsage.WRAP),
                arguments(Operation.UNWRAP, KeyUsage.UNWRAP),
                arguments(Operation.DERIVE_KEY, KeyUsage.DERIVE));
    }

    @ParameterizedTest
    @MethodSource("usageMappings")
    void deniesOperationWhenRequiredUsageIsMissing(Operation operation, KeyUsage usage) {
        Set<KeyUsage> otherUsages = usage == KeyUsage.DERIVE
                ? Set.of(KeyUsage.ENCRYPT)
                : Set.of(KeyUsage.DERIVE);
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, otherUsages);

        PolicyDecision decision = policy.evaluate(request(operation, key));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.KEY_USAGE_MISMATCH, decision.reasonCode());
    }

    @Test
    void ruleIdIsStable() {
        assertEquals("usage", policy.ruleId());
    }

    private static PolicyRequest request(Operation operation, KeyDescriptor key) {
        return PolicyRequest.builder(operation, TestFixtures.caller()).key(key).build();
    }
}
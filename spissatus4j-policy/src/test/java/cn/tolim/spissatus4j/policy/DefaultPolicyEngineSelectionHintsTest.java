package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.policy.AlgorithmPolicy;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.PolicyRule;
import cn.tolim.spissatus4j.contract.policy.PolicySnapshot;
import cn.tolim.spissatus4j.contract.policy.SelectionHints;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.policy.algorithm.DefaultAlgorithmPolicy;
import cn.tolim.spissatus4j.policy.decision.DefaultPolicyEngine;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultPolicyEngineSelectionHintsTest {

    @Test
    void singleAlgorithmPolicyContributesAllConstraints() {
        DefaultAlgorithmPolicy policy = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM, AlgorithmId.RSA_OAEP),
                Set.of(AlgorithmId.SHA_1),
                true,
                Map.of(AlgorithmId.AES_GCM, 256));
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(policy), List.of(), "engine-1");

        SelectionHints hints = engine.selectionHints(TestFixtures.caller());

        assertTrue(hints.available());
        assertEquals("engine-1", hints.sourceId());
        assertTrue(hints.allowListPresent());
        assertEquals(Set.of(AlgorithmId.AES_GCM, AlgorithmId.RSA_OAEP), hints.allowedAlgorithms());
        assertEquals(Set.of(AlgorithmId.SHA_1), hints.deniedAlgorithms());
        assertTrue(hints.allowExperimental());
        assertEquals(256, hints.minimumKeyBits(AlgorithmId.AES_GCM));
        assertEquals(2048, hints.minimumKeyBits(AlgorithmId.RSA_OAEP));
        assertEquals(0, hints.minimumKeyBits(AlgorithmId.SHA_1));
        assertTrue(hints.permits(AlgorithmId.AES_GCM));
        assertFalse(hints.permits(AlgorithmId.SHA_256));
        assertFalse(hints.permits(AlgorithmId.SHA_1));
    }

    @Test
    void multiplePoliciesIntersectAllowListsAndUnionDeniedAlgorithms() {
        DefaultAlgorithmPolicy first = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM, AlgorithmId.RSA_OAEP), Set.of(AlgorithmId.SHA_1), false);
        DefaultAlgorithmPolicy second = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM, AlgorithmId.SHA_256), Set.of(AlgorithmId.MD5), true);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(first, second), List.of(), "engine-1");

        SelectionHints hints = engine.selectionHints(TestFixtures.caller());

        assertTrue(hints.available());
        assertTrue(hints.allowListPresent());
        assertEquals(Set.of(AlgorithmId.AES_GCM), hints.allowedAlgorithms());
        assertEquals(Set.of(AlgorithmId.SHA_1, AlgorithmId.MD5), hints.deniedAlgorithms());
        assertFalse(hints.allowExperimental(), "strictest allowExperimental flag wins");
        assertTrue(hints.permits(AlgorithmId.AES_GCM));
        assertFalse(hints.permits(AlgorithmId.RSA_OAEP));
        assertFalse(hints.permits(AlgorithmId.SHA_256));
    }

    @Test
    void disjointAllowListsProducePresentButEmptyAllowedSet() {
        DefaultAlgorithmPolicy first = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM), Set.of(), false);
        DefaultAlgorithmPolicy second = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.RSA_OAEP), Set.of(), false);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(first, second), List.of(), "engine-1");

        SelectionHints hints = engine.selectionHints(TestFixtures.caller());

        assertTrue(hints.available());
        assertTrue(hints.allowListPresent());
        assertEquals(Set.of(), hints.allowedAlgorithms());
        assertFalse(hints.permits(AlgorithmId.AES_GCM));
        assertFalse(hints.permits(AlgorithmId.RSA_OAEP));
        assertFalse(hints.permits(AlgorithmId.SHA_256));
    }

    @Test
    void noAlgorithmPolicyReturnsAvailableHintsWithoutRestrictions() {
        PolicyRule plainRule = new PolicyRule() {
            @Override
            public String ruleId() {
                return "plain";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return PolicyDecision.allow("plain");
            }
        };
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(plainRule), List.of(), "engine-1");

        SelectionHints hints = engine.selectionHints(TestFixtures.caller());

        assertTrue(hints.available());
        assertEquals("engine-1", hints.sourceId());
        assertFalse(hints.allowListPresent());
        assertEquals(Set.of(), hints.allowedAlgorithms());
        assertEquals(Set.of(), hints.deniedAlgorithms());
        assertEquals(0, hints.minimumKeyBits(AlgorithmId.AES_GCM));
        assertFalse(hints.allowExperimental());
        assertTrue(hints.permits(AlgorithmId.AES_GCM));
        assertTrue(hints.permits(AlgorithmId.MD5));
    }

    @Test
    void providerIsNeverLoadedRefreshedOrHealthChecked() {
        AtomicBoolean providerTouched = new AtomicBoolean();
        PolicyProvider provider = new PolicyProvider() {
            @Override
            public String providerId() {
                return "provider-1";
            }

            @Override
            public PolicySnapshot load() {
                providerTouched.set(true);
                throw new IllegalStateException("selection hints must not load providers");
            }

            @Override
            public void refresh() {
                providerTouched.set(true);
                throw new IllegalStateException("selection hints must not refresh providers");
            }

            @Override
            public HealthStatus health() {
                providerTouched.set(true);
                throw new IllegalStateException("selection hints must not check provider health");
            }
        };
        DefaultAlgorithmPolicy policy = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM), Set.of(), false);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(policy), List.of(provider), "engine-1");

        SelectionHints hints = assertDoesNotThrow(
                () -> engine.selectionHints(TestFixtures.caller()));

        assertFalse(providerTouched.get(), "providers must not be consulted for selection hints");
        assertTrue(hints.available());
        assertEquals(Set.of(AlgorithmId.AES_GCM), hints.allowedAlgorithms());
    }

    @Test
    void throwingAlgorithmPolicyIsSkipped() {
        AlgorithmPolicy broken = new AlgorithmPolicy() {
            @Override
            public String ruleId() {
                return "broken";
            }

            @Override
            public Set<AlgorithmId> allowedAlgorithms() {
                throw new IllegalStateException("broken hint source");
            }

            @Override
            public Set<AlgorithmId> deniedAlgorithms() {
                return Set.of();
            }

            @Override
            public int minimumKeyBits(AlgorithmId algorithm) {
                return 0;
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return PolicyDecision.deny("TEST_DENY", "broken", "broken");
            }
        };
        DefaultAlgorithmPolicy valid = new DefaultAlgorithmPolicy(
                Set.of(AlgorithmId.AES_GCM), Set.of(AlgorithmId.SHA_1), false);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(broken, valid), List.of(), "engine-1");

        SelectionHints hints = assertDoesNotThrow(
                () -> engine.selectionHints(TestFixtures.caller()));

        assertTrue(hints.available());
        assertEquals(Set.of(AlgorithmId.AES_GCM), hints.allowedAlgorithms());
        assertEquals(Set.of(AlgorithmId.SHA_1), hints.deniedAlgorithms());
    }
}

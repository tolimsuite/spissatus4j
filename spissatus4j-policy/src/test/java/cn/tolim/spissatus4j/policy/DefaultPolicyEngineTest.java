package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.PolicyRule;
import cn.tolim.spissatus4j.contract.policy.PolicySnapshot;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.policy.access.DefaultAccessPolicy;
import cn.tolim.spissatus4j.policy.algorithm.DefaultAlgorithmPolicy;
import cn.tolim.spissatus4j.policy.decision.ComplianceRule;
import cn.tolim.spissatus4j.policy.decision.DefaultPolicyEngine;
import cn.tolim.spissatus4j.policy.tenant.DefaultTenantPolicy;
import cn.tolim.spissatus4j.policy.usage.DefaultUsagePolicy;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultPolicyEngineTest {

    private static final PolicyRequest REQUEST = TestFixtures.request(Operation.ENCRYPT,
            TestFixtures.caller());

    @Test
    void mergesStrictestDecision() {
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("allow"), warning("warn"), denying("deny")), List.of(), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals("deny", decision.policyId());
        assertEquals("TEST_DENY", decision.reasonCode());
    }

    @Test
    void warningWinsOverAllow() {
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("allow"), warning("warn")), List.of(), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertEquals(PolicyDecision.Outcome.WARN, decision.outcome());
        assertEquals("warn", decision.policyId());
        assertTrue(decision.allowed());
    }

    @Test
    void throwingRuleFailsClosedWithoutLeakingDetails() {
        PolicyRule broken = new PolicyRule() {
            @Override
            public String ruleId() {
                return "broken";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                throw new IllegalStateException("super-secret-material");
            }
        };
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(broken), List.of(), "test");

        PolicyDecision decision = assertDoesNotThrow(() -> engine.evaluate(REQUEST));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
        assertEquals("broken", decision.policyId());
        assertFalse(decision.message().contains("super-secret-material"));
    }

    @Test
    void nullRuleDecisionFailsClosed() {
        PolicyRule nullDecision = new PolicyRule() {
            @Override
            public String ruleId() {
                return "silent";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return null;
            }
        };
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(nullDecision), List.of(), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
        assertEquals("silent", decision.policyId());
    }

    @Test
    void ruleWithDownHealthDenies() {
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(unhealthy("sick", HealthStatus.DOWN), allowing("allow")), List.of(), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
        assertEquals("sick", decision.policyId());
    }

    @Test
    void ruleHealthExceptionDenies() {
        PolicyRule brokenHealth = new PolicyRule() {
            @Override
            public String ruleId() {
                return "broken-health";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return PolicyDecision.allow("broken-health");
            }

            @Override
            public HealthStatus health() {
                throw new IllegalStateException("health failure");
            }
        };
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(brokenHealth), List.of(), "test");

        assertTrue(engine.evaluate(REQUEST).denied());
        assertEquals(HealthStatus.DOWN, engine.health());
    }

    @Test
    void providerWithDownHealthDenies() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.DOWN);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("allow")), List.of(provider), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
        assertEquals("provider-1", decision.policyId());
    }

    @Test
    void providerLoadExceptionDenies() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.UP);
        provider.snapshot = () -> {
            throw new IllegalStateException("source offline");
        };
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("allow")), List.of(provider), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
        assertEquals(HealthStatus.DOWN, engine.health());
    }

    @Test
    void nullProviderSnapshotDenies() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.UP);
        provider.snapshot = () -> null;
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("allow")), List.of(provider), "test");

        assertTrue(engine.evaluate(REQUEST).denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, engine.evaluate(REQUEST).reasonCode());
    }

    @Test
    void providerRulesParticipateInDecision() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.UP);
        provider.snapshot = () -> new PolicySnapshot(1, List.of(denying("remote")),
                TestFixtures.NOW);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("local")), List.of(provider), "test");

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals("remote", decision.policyId());
        assertEquals("TEST_DENY", decision.reasonCode());
    }

    @Test
    void degradedProviderIsStillEvaluated() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.DEGRADED);
        provider.snapshot = () -> new PolicySnapshot(1, List.of(allowing("remote")),
                TestFixtures.NOW);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("local")), List.of(provider), "test");

        assertTrue(engine.evaluate(REQUEST).allowed());
        assertEquals(HealthStatus.DEGRADED, engine.health());
    }

    @Test
    void emptyEngineFailsClosed() {
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of());

        PolicyDecision decision = engine.evaluate(REQUEST);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
    }

    @Test
    void healthAggregatesRulesAndProviders() {
        DefaultPolicyEngine up = new DefaultPolicyEngine(List.of(allowing("allow")), List.of(), "test");
        assertEquals(HealthStatus.UP, up.health());

        DefaultPolicyEngine degraded = new DefaultPolicyEngine(
                List.of(unhealthy("degraded", HealthStatus.DEGRADED)), List.of(), "test");
        assertEquals(HealthStatus.DEGRADED, degraded.health());

        DefaultPolicyEngine down = new DefaultPolicyEngine(
                List.of(unhealthy("down", HealthStatus.DOWN), allowing("allow")), List.of(), "test");
        assertEquals(HealthStatus.DOWN, down.health());

        StubProvider provider = new StubProvider("provider-1", HealthStatus.DOWN);
        DefaultPolicyEngine providerDown = new DefaultPolicyEngine(
                List.of(allowing("allow")), List.of(provider), "test");
        assertEquals(HealthStatus.DOWN, providerDown.health());
    }

    @Test
    void refreshFailureDoesNotThrowAndIsReflectedInHealth() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.UP);
        provider.refreshFails = true;
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("allow")), List.of(provider), "test");

        assertDoesNotThrow(engine::refresh);
        assertEquals(HealthStatus.DOWN, engine.health());

        provider.refreshFails = false;
        assertDoesNotThrow(engine::refresh);
        assertEquals(HealthStatus.UP, engine.health());
    }

    @Test
    void failedProviderRefreshDeniesEvaluationUntilSuccessfulRefresh() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.UP);
        provider.snapshot = () -> new PolicySnapshot(1, List.of(allowing("remote")),
                TestFixtures.NOW);
        provider.refreshFails = true;
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("local")), List.of(provider), "test");

        assertDoesNotThrow(engine::refresh);
        assertEquals(HealthStatus.DOWN, engine.health());

        PolicyDecision denied = engine.evaluate(REQUEST);
        assertTrue(denied.denied(), "stale provider rules must not be used after a failed refresh");
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, denied.reasonCode());
        assertEquals("provider-1", denied.policyId());

        provider.refreshFails = false;
        engine.refresh();
        assertEquals(HealthStatus.UP, engine.health());
        assertTrue(engine.evaluate(REQUEST).allowed(), "a successful refresh restores evaluation");
    }

    @Test
    void providerWhoseLoadFailsAfterSuccessfulRefreshDenies() {
        StubProvider provider = new StubProvider("provider-1", HealthStatus.UP);
        provider.snapshot = () -> new PolicySnapshot(1, List.of(allowing("remote")),
                TestFixtures.NOW);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(
                List.of(allowing("local")), List.of(provider), "test");
        engine.refresh();
        assertTrue(engine.evaluate(REQUEST).allowed());

        provider.snapshot = () -> {
            throw new IllegalStateException("stale source");
        };

        PolicyDecision denied = engine.evaluate(REQUEST);
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, denied.reasonCode());
        assertEquals(HealthStatus.DOWN, engine.health());
    }

    @Test
    void defaultRulesAllowAesGcmForAuthenticatedCaller() {
        DefaultPolicyEngine engine = defaultEngine();

        PolicyRequest request = PolicyRequest.builder(Operation.ENCRYPT, TestFixtures.caller())
                .algorithm(AlgorithmId.AES_GCM)
                .build();

        PolicyDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(PolicyDecision.Outcome.ALLOW, decision.outcome());
    }

    @Test
    void defaultRulesDenyMd5AndAnonymousCallers() {
        DefaultPolicyEngine engine = defaultEngine();

        PolicyDecision md5 = engine.evaluate(PolicyRequest.builder(Operation.DIGEST,
                TestFixtures.caller()).algorithm(AlgorithmId.MD5).build());
        assertTrue(md5.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, md5.reasonCode());

        PolicyDecision anonymous = engine.evaluate(PolicyRequest.of(Operation.ENCRYPT,
                CallerContext.anonymous()));
        assertTrue(anonymous.denied());
        assertEquals(ReasonCodes.ANONYMOUS_CALLER, anonymous.reasonCode());
    }

    @Test
    void engineIdIsStableAndValidated() {
        assertEquals("policy", new DefaultPolicyEngine(List.of()).engineId());
        assertEquals("custom", new DefaultPolicyEngine(List.of(), List.of(), "custom").engineId());
        assertThrows(IllegalArgumentException.class,
                () -> new DefaultPolicyEngine(List.of(), List.of(), " "));

        DefaultPolicyEngine nullLists = new DefaultPolicyEngine(null, null, "test");
        assertEquals(List.of(), nullLists.rules());
        assertEquals(List.of(), nullLists.providers());
    }

    @Test
    void nullRequestFailsClosed() {
        DefaultPolicyEngine engine = new DefaultPolicyEngine(List.of(allowing("allow")));

        PolicyDecision decision = engine.evaluate(null);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
    }

    private static DefaultPolicyEngine defaultEngine() {
        List<PolicyRule> rules = List.of(
                new DefaultAccessPolicy(),
                new DefaultTenantPolicy(),
                new DefaultAlgorithmPolicy(),
                new DefaultUsagePolicy(),
                new ComplianceRule());
        return new DefaultPolicyEngine(rules, List.of(), "policy");
    }

    private static PolicyRule fixed(String id, PolicyDecision decision) {
        return new PolicyRule() {
            @Override
            public String ruleId() {
                return id;
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return decision;
            }
        };
    }

    private static PolicyRule allowing(String id) {
        return fixed(id, PolicyDecision.allow(id));
    }

    private static PolicyRule warning(String id) {
        return fixed(id, PolicyDecision.warn("TEST_WARN", "warning", id));
    }

    private static PolicyRule denying(String id) {
        return fixed(id, PolicyDecision.deny("TEST_DENY", "denied", id));
    }

    private static PolicyRule unhealthy(String id, HealthStatus health) {
        return new PolicyRule() {
            @Override
            public String ruleId() {
                return id;
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return PolicyDecision.allow(id);
            }

            @Override
            public HealthStatus health() {
                return health;
            }
        };
    }

    private static final class StubProvider implements PolicyProvider {
        private final String id;
        private final HealthStatus health;
        private Supplier<PolicySnapshot> snapshot = () -> null;
        private boolean refreshFails;

        private StubProvider(String id, HealthStatus health) {
            this.id = id;
            this.health = health;
        }

        @Override
        public String providerId() {
            return id;
        }

        @Override
        public PolicySnapshot load() {
            return snapshot.get();
        }

        @Override
        public HealthStatus health() {
            return health;
        }

        @Override
        public void refresh() {
            if (refreshFails) {
                throw new IllegalStateException("refresh failed");
            }
        }
    }
}
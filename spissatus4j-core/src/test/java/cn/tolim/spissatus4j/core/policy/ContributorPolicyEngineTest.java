package cn.tolim.spissatus4j.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ContributorPolicyEngineTest {

    private static final PolicyRequest REQUEST = PolicyRequest.of(Operation.ENCRYPT,
            CallerContext.of("caller", "tenant", Set.of("crypto-user")));

    private static PolicyEngine allowAll() {
        return new PolicyEngine() {
            @Override
            public String engineId() {
                return "base";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return PolicyDecision.allow("base");
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.UP;
            }
        };
    }

    private static PolicyProvider provider(String id, HealthStatus health, PolicySnapshot snapshot,
                                           boolean refreshFails) {
        return new PolicyProvider() {
            @Override
            public String providerId() {
                return id;
            }

            @Override
            public PolicySnapshot load() {
                return snapshot;
            }

            @Override
            public void refresh() {
                if (refreshFails) {
                    throw new IllegalStateException("refresh failed");
                }
            }

            @Override
            public HealthStatus health() {
                return health;
            }
        };
    }

    private static PolicyRule rule(PolicyDecision decision) {
        return new PolicyRule() {
            @Override
            public String ruleId() {
                return "provider-rule";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                return decision;
            }
        };
    }

    private static PolicyRule throwingRule() {
        return new PolicyRule() {
            @Override
            public String ruleId() {
                return "throwing-rule";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                throw new IllegalStateException("boom");
            }
        };
    }

    @Test
    void providerRulesMergeStrictest() {
        PolicySnapshot snapshot = new PolicySnapshot(1,
                List.of(rule(PolicyDecision.deny(ReasonCodes.ALGORITHM_PROHIBITED,
                        "denied", "provider-rule"))), Instant.now());
        ContributorPolicyEngine engine = new ContributorPolicyEngine(allowAll(),
                List.of(provider("remote", HealthStatus.UP, snapshot, false)));
        assertTrue(engine.evaluate(REQUEST).denied());
        assertEquals(HealthStatus.UP, engine.health());
    }

    @Test
    void providerFailureFailsClosed() {
        ContributorPolicyEngine down = new ContributorPolicyEngine(allowAll(),
                List.of(provider("down", HealthStatus.DOWN, null, false)));
        assertTrue(down.evaluate(REQUEST).denied());
        assertEquals(HealthStatus.DOWN, down.health());

        ContributorPolicyEngine nullSnapshot = new ContributorPolicyEngine(allowAll(),
                List.of(provider("null", HealthStatus.UP, null, false)));
        assertTrue(nullSnapshot.evaluate(REQUEST).denied());

        ContributorPolicyEngine refreshFailure = new ContributorPolicyEngine(allowAll(),
                List.of(provider("refresh", HealthStatus.UP,
                        new PolicySnapshot(1, List.of(), Instant.now()), true)));
        refreshFailure.refresh();
        assertTrue(refreshFailure.evaluate(REQUEST).denied());
        assertEquals(HealthStatus.DOWN, refreshFailure.health());
    }

    @Test
    void providerRuleExceptionFailsClosed() {
        PolicySnapshot snapshot = new PolicySnapshot(1, List.of(throwingRule()), Instant.now());
        ContributorPolicyEngine engine = new ContributorPolicyEngine(allowAll(),
                List.of(provider("throwing", HealthStatus.UP, snapshot, false)));
        assertTrue(engine.evaluate(REQUEST).denied());
    }
}
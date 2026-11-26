package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.policy.access.DefaultAccessPolicy;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultAccessPolicyTest {

    @Test
    void allowsAuthenticatedCallerByDefault() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy();

        PolicyDecision decision = policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller()));

        assertTrue(decision.allowed());
        assertEquals("access", decision.policyId());
    }

    @Test
    void deniesAnonymousCallerByDefault() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy();

        PolicyDecision decision = policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                CallerContext.anonymous()));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ANONYMOUS_CALLER, decision.reasonCode());
    }

    @Test
    void allowsAnonymousCallerWhenConfigured() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy(true, Set.of(), "", Set.of(), 0, 0,
                Clock.fixed(TestFixtures.NOW, ZoneOffset.UTC));

        assertTrue(policy.allowAnonymous());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                CallerContext.anonymous())).allowed());
    }

    @Test
    void callerAllowListIsEnforced() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of("svc-a"), "", Set.of(),
                0, 0, Clock.fixed(TestFixtures.NOW, ZoneOffset.UTC));

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"))).allowed());

        PolicyDecision denied = policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", TestFixtures.TENANT, "user")));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.CALLER_NOT_AUTHORIZED, denied.reasonCode());
        assertEquals(Set.of("svc-a"), policy.allowedCallers());
    }

    @Test
    void requiredRoleIsEnforced() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "admin", Set.of(),
                0, 0, Clock.fixed(TestFixtures.NOW, ZoneOffset.UTC));

        PolicyDecision denied = policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user")));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.CALLER_NOT_AUTHORIZED, denied.reasonCode());

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user", "admin"))).allowed());
    }

    @Test
    void allowedEnvironmentsAreEnforced() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of("prod"),
                0, 0, Clock.fixed(TestFixtures.NOW, ZoneOffset.UTC));

        PolicyDecision denied = policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                new CallerContext("svc-a", TestFixtures.TENANT, Set.of(), "dev", Map.of())));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.CALLER_NOT_AUTHORIZED, denied.reasonCode());

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                new CallerContext("svc-a", TestFixtures.TENANT, Set.of(), "prod", Map.of()))).allowed());
    }

    @Test
    void rateLimitDeniesAfterCapacityIsExhausted() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                2, 0, clock);
        CallerContext caller = TestFixtures.caller();

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());

        PolicyDecision third = policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller));
        assertTrue(third.denied());
        assertEquals(ReasonCodes.RATE_LIMITED, third.reasonCode());
        assertEquals(2, policy.rateLimitPerMinute());
    }

    @Test
    void rateLimitRefillsOverTime() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                2, 0, clock);
        CallerContext caller = TestFixtures.caller();

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).denied());

        clock.advance(Duration.ofMinutes(1));

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).denied());
    }

    @Test
    void rateLimitIsPerCaller() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                1, 0, clock);

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"))).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"))).denied());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", TestFixtures.TENANT, "user"))).allowed());
    }

    @Test
    void rateLimitBucketsAreScopedByTenantAndCaller() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                1, 0, clock);

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", "tenant-a", "user"))).allowed());
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", "tenant-a", "user"))).denied());

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                        TestFixtures.caller("svc-a", "tenant-b", "user"))).allowed(),
                "the same caller id in another tenant has an independent bucket");
        assertEquals(2, policy.trackedBucketCount());
    }

    @Test
    void idleBucketsAreEvicted() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                1, 0, clock);

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"))).allowed());
        assertEquals(1, policy.trackedBucketCount());

        clock.advance(Duration.ofMillis(DefaultAccessPolicy.BUCKET_RETENTION_MILLIS));

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", TestFixtures.TENANT, "user"))).allowed());
        assertEquals(1, policy.trackedBucketCount(),
                "the idle caller bucket is evicted instead of retained forever");
    }

    @Test
    void existingBucketIsNeverEvictedByTheBoundCheck() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                1, 0, clock);
        var oldest = TestFixtures.caller("svc-oldest", TestFixtures.TENANT, "user");
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, oldest)).allowed());

        for (int i = 0; i < DefaultAccessPolicy.MAX_TRACKED_BUCKETS - 1; i++) {
            assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                    TestFixtures.caller("fill-" + i, "tenant-" + i, "user"))).allowed());
        }
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, oldest)).denied(),
                "the charged bucket must not be evicted and re-filled by the size bound");
    }

    @Test
    void trackedBucketMapIsBoundedUnderManyIdentities() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                1, 0, clock);

        int identities = DefaultAccessPolicy.MAX_TRACKED_BUCKETS * 2;
        for (int i = 0; i < identities; i++) {
            assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                    TestFixtures.caller("svc-" + i, "tenant-" + i, "user"))).allowed());
        }

        assertTrue(policy.trackedBucketCount() <= DefaultAccessPolicy.MAX_TRACKED_BUCKETS,
                "bucket map size must stay bounded");
    }

    @Test
    void tenantQuotaIsEnforced() {
        MutableClock clock = new MutableClock(TestFixtures.NOW);
        DefaultAccessPolicy policy = new DefaultAccessPolicy(false, Set.of(), "", Set.of(),
                0, 1, clock);

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"))).allowed());

        PolicyDecision denied = policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", TestFixtures.TENANT, "user")));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.QUOTA_EXCEEDED, denied.reasonCode());

        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT,
                TestFixtures.caller("svc-c", "tenant-b", "user"))).allowed());
        assertEquals(1, policy.tenantQuotaPerMinute());
    }

    @Test
    void disabledLimitsAllowAllCalls() {
        DefaultAccessPolicy policy = new DefaultAccessPolicy();
        CallerContext caller = TestFixtures.caller();

        for (int i = 0; i < 100; i++) {
            assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, caller)).allowed());
        }
        assertEquals(0, policy.rateLimitPerMinute());
        assertEquals(0, policy.tenantQuotaPerMinute());
    }

    @Test
    void ruleIdIsStable() {
        assertEquals("access", new DefaultAccessPolicy().ruleId());
    }

    @Test
    void negativeLimitsAreRejected() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new DefaultAccessPolicy(false, Set.of(), "", Set.of(), -1, 0,
                        Clock.systemUTC()));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new DefaultAccessPolicy(false, Set.of(), "", Set.of(), 0, -1,
                        Clock.systemUTC()));
    }

    @Test
    void nullRequestFailsClosed() {
        PolicyRequest request = null;
        PolicyDecision decision = new DefaultAccessPolicy().evaluate(request);

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.POLICY_UNAVAILABLE, decision.reasonCode());
    }
}
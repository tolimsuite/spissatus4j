package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.policy.tenant.DefaultTenantPolicy;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultTenantPolicyTest {

    private final DefaultTenantPolicy policy = new DefaultTenantPolicy();

    @Test
    void sameTenantIsAllowed() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                TestFixtures.TENANT, 256, AlgorithmId.AES_GCM, null);

        PolicyDecision decision = policy.evaluate(request(key, TestFixtures.caller()));

        assertTrue(decision.allowed());
        assertEquals("tenant", decision.policyId());
    }

    @Test
    void requestWithoutKeyDescriptorIsAllowed() {
        assertTrue(policy.evaluate(TestFixtures.request(Operation.ENCRYPT, TestFixtures.caller())).allowed());
    }

    @Test
    void crossTenantAccessIsDeniedByDefault() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                "tenant-b", 256, AlgorithmId.AES_GCM, null);

        PolicyDecision decision = policy.evaluate(request(key,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user")));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.TENANT_MISMATCH, decision.reasonCode());
        assertEquals(Set.of(DefaultTenantPolicy.CROSS_TENANT_ROLE,
                DefaultTenantPolicy.ADMIN_ROLE), policy.crossTenantRoles());
    }

    @Test
    void crossTenantRoleAllowsOtherTenantsKey() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                "tenant-b", 256, AlgorithmId.AES_GCM, null);

        PolicyDecision decision = policy.evaluate(request(key,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user", "crypto-cross-tenant")));

        assertTrue(decision.allowed());
    }

    @Test
    void adminRoleAllowsOtherTenantsKey() {
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                "tenant-b", 256, AlgorithmId.AES_GCM, null);

        assertTrue(policy.evaluate(request(key,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "crypto-admin"))).allowed());
    }

    @Test
    void allowedTenantsRestrictCallerRegardlessOfKeyTenant() {
        DefaultTenantPolicy restricted = new DefaultTenantPolicy(Set.of(TestFixtures.TENANT));
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                "tenant-b", 256, AlgorithmId.AES_GCM, null);

        PolicyDecision decision = restricted.evaluate(request(key,
                TestFixtures.caller("svc-a", "tenant-c", "crypto-admin")));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.TENANT_MISMATCH, decision.reasonCode());
        assertEquals(Set.of(TestFixtures.TENANT), restricted.allowedTenants());
    }

    @Test
    void allowedTenantCallerIsAllowed() {
        DefaultTenantPolicy restricted = new DefaultTenantPolicy(Set.of(TestFixtures.TENANT));
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                TestFixtures.TENANT, 256, AlgorithmId.AES_GCM, null);

        assertTrue(restricted.evaluate(request(key, TestFixtures.caller())).allowed());
    }

    @Test
    void customCrossTenantRolesReplaceDefaults() {
        DefaultTenantPolicy custom = new DefaultTenantPolicy(Set.of(), Set.of("break-glass"));
        KeyDescriptor key = TestFixtures.key(KeyState.ACTIVE, Set.of(KeyUsage.ENCRYPT),
                "tenant-b", 256, AlgorithmId.AES_GCM, null);

        assertTrue(custom.evaluate(request(key,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "crypto-admin"))).denied());
        assertTrue(custom.evaluate(request(key,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "break-glass"))).allowed());
    }

    @Test
    void targetTenantAttributeIsEnforcedForCreationAndListing() {
        PolicyRequest foreign = PolicyRequest.builder(Operation.GENERATE_KEY,
                        TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"))
                .attributes(Map.of("targetTenant", "tenant-b")).build();
        assertTrue(policy.evaluate(foreign).denied());

        PolicyRequest admin = PolicyRequest.builder(Operation.GENERATE_KEY,
                        TestFixtures.caller("svc-a", TestFixtures.TENANT, "crypto-admin"))
                .attributes(Map.of("targetTenant", "tenant-b")).build();
        assertTrue(policy.evaluate(admin).allowed());
    }

    @Test
    void ruleIdIsStable() {
        assertEquals("tenant", policy.ruleId());
    }

    private static PolicyRequest request(KeyDescriptor key, cn.tolim.spissatus4j.contract.policy.CallerContext caller) {
        return PolicyRequest.builder(Operation.ENCRYPT, caller).key(key).build();
    }
}
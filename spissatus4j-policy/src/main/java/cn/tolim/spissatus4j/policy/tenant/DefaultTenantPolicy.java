package cn.tolim.spissatus4j.policy.tenant;

import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.policy.TenantPolicy;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Default tenant isolation policy.
 *
 * <p>The caller's tenant must match the key descriptor's tenant. Cross-tenant
 * access is denied unless the caller carries a configured cross-tenant role
 * (by default {@code crypto-cross-tenant} or {@code crypto-admin}). An optional
 * allow-list additionally restricts which caller tenants may be served at
 * all, regardless of role.</p>
 */
public final class DefaultTenantPolicy implements TenantPolicy {

    /** Stable, non-sensitive policy identifier. */
    public static final String RULE_ID = "tenant";

    /** Default role permitting access to keys of another tenant. */
    public static final String CROSS_TENANT_ROLE = "crypto-cross-tenant";

    /** Default administrative role permitting cross-tenant access. */
    public static final String ADMIN_ROLE = "crypto-admin";

    private final Set<String> allowedTenants;
    private final Set<String> crossTenantRoles;

    /**
     * Creates the default policy: no tenant allow-list and the default
     * cross-tenant roles.
     */
    public DefaultTenantPolicy() {
        this(Set.of());
    }

    /**
     * Creates a policy with a tenant allow-list and the default cross-tenant
     * roles.
     *
     * @param allowedTenants caller tenants that may be served; empty allows any tenant
     */
    public DefaultTenantPolicy(Set<String> allowedTenants) {
        this(allowedTenants, Set.of(CROSS_TENANT_ROLE, ADMIN_ROLE));
    }

    /**
     * Creates a fully configured policy.
     *
     * @param allowedTenants caller tenants that may be served; empty allows any tenant
     * @param crossTenantRoles roles that permit access to another tenant's keys
     */
    public DefaultTenantPolicy(Set<String> allowedTenants, Set<String> crossTenantRoles) {
        this.allowedTenants = copyNames(allowedTenants);
        this.crossTenantRoles = copyNames(crossTenantRoles);
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    public Set<String> allowedTenants() {
        return allowedTenants;
    }

    public Set<String> crossTenantRoles() {
        return crossTenantRoles;
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        if (request == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No policy request available", RULE_ID);
        }
        CallerContext caller = request.caller();
        if (caller == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No caller identity available", RULE_ID);
        }
        if (!allowedTenants.isEmpty() && !allowedTenants.contains(caller.tenantId())) {
            return PolicyDecision.deny(ReasonCodes.TENANT_MISMATCH,
                    "Caller tenant is not permitted", RULE_ID);
        }
        String targetTenant = request.attributes().get("targetTenant");
        if (targetTenant != null && !targetTenant.isBlank()
                && !targetTenant.trim().equals(caller.tenantId())
                && !hasCrossTenantRole(caller)) {
            return PolicyDecision.deny(ReasonCodes.TENANT_MISMATCH,
                    "Cross-tenant key creation or listing is denied", RULE_ID);
        }
        KeyDescriptor key = request.key();
        if (key == null) {
            return PolicyDecision.allow(RULE_ID);
        }
        if (key.tenantId().equals(caller.tenantId())) {
            return PolicyDecision.allow(RULE_ID);
        }
        if (hasCrossTenantRole(caller)) {
            return PolicyDecision.allow(RULE_ID);
        }
        return PolicyDecision.deny(ReasonCodes.TENANT_MISMATCH,
                "Key belongs to a different tenant", RULE_ID);
    }

    private boolean hasCrossTenantRole(CallerContext caller) {
        for (String role : crossTenantRoles) {
            if (caller.hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> copyNames(Set<String> source) {
        if (source == null || source.isEmpty()) {
            return Set.of();
        }
        LinkedHashSet<String> copy = new LinkedHashSet<>();
        for (String value : source) {
            Objects.requireNonNull(value, "value");
            String trimmed = value.trim();
            if (!trimmed.isEmpty()) {
                copy.add(trimmed);
            }
        }
        return Set.copyOf(copy);
    }
}
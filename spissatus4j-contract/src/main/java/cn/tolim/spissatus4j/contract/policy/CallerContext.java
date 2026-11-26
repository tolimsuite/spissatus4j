package cn.tolim.spissatus4j.contract.policy;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Identity of the caller on whose behalf a cryptographic operation is
 * performed. Access policies deny anonymous callers by default.
 *
 * @param callerId stable caller identity (service, user or job)
 * @param tenantId tenant isolation domain
 * @param roles granted roles
 * @param environment deployment environment (for example prod, staging)
 * @param attributes additional non-secret claims
 */
public record CallerContext(
        String callerId,
        String tenantId,
        Set<String> roles,
        String environment,
        Map<String, String> attributes) {

    public CallerContext {
        callerId = Objects.requireNonNull(callerId, "callerId").trim();
        if (callerId.isEmpty() || callerId.length() > 128) {
            throw new IllegalArgumentException("Invalid callerId");
        }
        tenantId = Objects.requireNonNull(tenantId, "tenantId").trim();
        if (tenantId.isEmpty() || tenantId.length() > 128) {
            throw new IllegalArgumentException("Invalid tenantId");
        }
        roles = Set.copyOf(Objects.requireNonNull(roles, "roles"));
        environment = environment == null ? "default" : environment;
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    public static CallerContext of(String callerId, String tenantId, Set<String> roles) {
        return new CallerContext(callerId, tenantId, roles, "default", Map.of());
    }

    public static CallerContext system() {
        return new CallerContext("system", "system", Set.of("system", "crypto-admin"), "system", Map.of());
    }

    public static CallerContext anonymous() {
        return new CallerContext("anonymous", "default", Set.of(), "default", Map.of());
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean isAnonymous() {
        return "anonymous".equals(callerId);
    }
}
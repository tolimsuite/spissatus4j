package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/** Shared deterministic test fixtures; carries no secrets. */
final class TestFixtures {

    static final Instant CREATED = Instant.parse("2025-01-01T00:00:00Z");
    static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    static final String TENANT = "tenant-a";

    private TestFixtures() {
    }

    static CallerContext caller() {
        return caller("svc-a", TENANT, "user");
    }

    static CallerContext caller(String callerId, String tenantId, String... roles) {
        return new CallerContext(callerId, tenantId, Set.of(roles), "default", Map.of());
    }

    static CallerContext caller(String callerId, String tenantId, String environment, Set<String> roles) {
        return new CallerContext(callerId, tenantId, roles, environment, Map.of());
    }

    static PolicyRequest request(Operation operation, CallerContext caller) {
        return PolicyRequest.of(operation, caller);
    }

    static KeyDescriptor key(KeyState state, Set<KeyUsage> usages) {
        return key(state, usages, TENANT, 256, AlgorithmId.AES_GCM, null);
    }

    static KeyDescriptor key(KeyState state, Set<KeyUsage> usages, String tenantId,
                             int keyBits, AlgorithmId algorithm, Instant expiresAt) {
        KeyType type = switch (algorithm.family()) {
            case ASYMMETRIC, KEM, SIGNATURE -> KeyType.RSA;
            default -> KeyType.AES;
        };
        return KeyDescriptor.builder()
                .keyId(KeyId.of("key-1"))
                .version(KeyVersion.first())
                .type(type)
                .algorithm(algorithm)
                .keyBits(keyBits)
                .state(state)
                .usages(usages)
                .tenantId(tenantId)
                .createdAt(CREATED)
                .activatedAt(CREATED)
                .expiresAt(expiresAt)
                .build();
    }
}
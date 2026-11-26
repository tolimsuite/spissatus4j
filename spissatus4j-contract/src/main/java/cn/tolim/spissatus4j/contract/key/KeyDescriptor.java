package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Non-secret metadata of a managed key version.
 *
 * <p>The descriptor never carries key material. Attributes must contain
 * operational metadata only; secrets are rejected by policy if supplied.</p>
 */
public record KeyDescriptor(
        KeyId keyId,
        KeyVersion version,
        KeyType type,
        AlgorithmId algorithm,
        int keyBits,
        KeyState state,
        Set<KeyUsage> usages,
        String tenantId,
        Instant createdAt,
        Instant activatedAt,
        Instant expiresAt,
        RotationPolicy rotationPolicy,
        boolean exportable,
        long usageCount,
        Map<String, String> attributes,
        String fingerprint) {

    public KeyDescriptor {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(state, "state");
        usages = Set.copyOf(Objects.requireNonNull(usages, "usages"));
        if (usages.isEmpty()) {
            throw new IllegalArgumentException("A key must have at least one usage");
        }
        tenantId = Objects.requireNonNull(tenantId, "tenantId");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        Objects.requireNonNull(createdAt, "createdAt");
        if (keyBits < 0 || usageCount < 0) {
            throw new IllegalArgumentException("Numeric metadata must not be negative");
        }
        if (expiresAt != null && expiresAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("expiresAt must not precede createdAt");
        }
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    public boolean supportsUsage(KeyUsage usage) {
        return usages.contains(usage);
    }

    public boolean isActive() {
        return state == KeyState.ACTIVE;
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    public KeyDescriptor withState(KeyState newState, Instant activated) {
        return new KeyDescriptor(keyId, version, type, algorithm, keyBits, newState, usages, tenantId,
                createdAt, activated, expiresAt, rotationPolicy, exportable, usageCount, attributes, fingerprint);
    }

    public KeyDescriptor withUsageCount(long count) {
        return new KeyDescriptor(keyId, version, type, algorithm, keyBits, state, usages, tenantId,
                createdAt, activatedAt, expiresAt, rotationPolicy, exportable, count, attributes, fingerprint);
    }

    public KeyDescriptor withExpiresAt(Instant expiry) {
        return new KeyDescriptor(keyId, version, type, algorithm, keyBits, state, usages, tenantId,
                createdAt, activatedAt, expiry, rotationPolicy, exportable, usageCount, attributes, fingerprint);
    }

    public KeyDescriptor withFingerprint(String newFingerprint) {
        return new KeyDescriptor(keyId, version, type, algorithm, keyBits, state, usages, tenantId,
                createdAt, activatedAt, expiresAt, rotationPolicy, exportable, usageCount, attributes, newFingerprint);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return "KeyDescriptor[keyId=" + keyId + ", version=" + version + ", type=" + type
                + ", algorithm=" + algorithm + ", state=" + state + ", tenantId=" + tenantId
                + ", usageCount=" + usageCount + "]";
    }

    /** Mutable builder for descriptors assembled by key providers and the key manager. */
    public static final class Builder {
        private KeyId keyId;
        private KeyVersion version;
        private KeyType type;
        private AlgorithmId algorithm;
        private int keyBits;
        private KeyState state = KeyState.PRE_ACTIVATION;
        private Set<KeyUsage> usages = Set.of();
        private String tenantId = "default";
        private Instant createdAt = Instant.now();
        private Instant activatedAt;
        private Instant expiresAt;
        private RotationPolicy rotationPolicy;
        private boolean exportable;
        private long usageCount;
        private Map<String, String> attributes = Map.of();
        private String fingerprint;

        public Builder keyId(KeyId value) {
            this.keyId = value;
            return this;
        }

        public Builder version(KeyVersion value) {
            this.version = value;
            return this;
        }

        public Builder type(KeyType value) {
            this.type = value;
            return this;
        }

        public Builder algorithm(AlgorithmId value) {
            this.algorithm = value;
            return this;
        }

        public Builder keyBits(int value) {
            this.keyBits = value;
            return this;
        }

        public Builder state(KeyState value) {
            this.state = value;
            return this;
        }

        public Builder usages(Set<KeyUsage> value) {
            this.usages = value;
            return this;
        }

        public Builder tenantId(String value) {
            this.tenantId = value;
            return this;
        }

        public Builder createdAt(Instant value) {
            this.createdAt = value;
            return this;
        }

        public Builder activatedAt(Instant value) {
            this.activatedAt = value;
            return this;
        }

        public Builder expiresAt(Instant value) {
            this.expiresAt = value;
            return this;
        }

        public Builder rotationPolicy(RotationPolicy value) {
            this.rotationPolicy = value;
            return this;
        }

        public Builder exportable(boolean value) {
            this.exportable = value;
            return this;
        }

        public Builder usageCount(long value) {
            this.usageCount = value;
            return this;
        }

        public Builder attributes(Map<String, String> value) {
            this.attributes = value;
            return this;
        }

        public Builder fingerprint(String value) {
            this.fingerprint = value;
            return this;
        }

        public KeyDescriptor build() {
            return new KeyDescriptor(keyId, version, type, algorithm, keyBits, state, usages, tenantId,
                    createdAt, activatedAt, expiresAt, rotationPolicy, exportable, usageCount, attributes,
                    fingerprint);
        }
    }
}
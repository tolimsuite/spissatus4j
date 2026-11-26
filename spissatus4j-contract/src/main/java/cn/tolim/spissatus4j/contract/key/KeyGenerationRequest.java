package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Request to generate a new logical key. A null {@link #keyId()} asks the
 * manager to create a random identifier. {@code keyBits == 0} selects the
 * algorithm's default size.
 */
public record KeyGenerationRequest(
        KeyId keyId,
        KeyType type,
        AlgorithmId algorithm,
        int keyBits,
        Set<KeyUsage> usages,
        String tenantId,
        RotationPolicy rotationPolicy,
        boolean exportable,
        Map<String, String> attributes) {

    public KeyGenerationRequest {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(algorithm, "algorithm");
        usages = Set.copyOf(Objects.requireNonNull(usages, "usages"));
        if (usages.isEmpty()) {
            throw new IllegalArgumentException("At least one key usage is required");
        }
        if (keyBits < 0) {
            throw new IllegalArgumentException("keyBits must not be negative");
        }
        tenantId = tenantId == null ? "default" : tenantId;
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    public static Builder builder(KeyType type, AlgorithmId algorithm, Set<KeyUsage> usages) {
        return new Builder().type(type).algorithm(algorithm).usages(usages);
    }

    public static final class Builder {
        private KeyId keyId;
        private KeyType type;
        private AlgorithmId algorithm;
        private int keyBits;
        private Set<KeyUsage> usages = Set.of();
        private String tenantId = "default";
        private RotationPolicy rotationPolicy = RotationPolicy.defaults();
        private boolean exportable;
        private Map<String, String> attributes = Map.of();

        public Builder keyId(KeyId value) {
            this.keyId = value;
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

        public Builder usages(Set<KeyUsage> value) {
            this.usages = value;
            return this;
        }

        public Builder tenantId(String value) {
            this.tenantId = value;
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

        public Builder attributes(Map<String, String> value) {
            this.attributes = value;
            return this;
        }

        public KeyGenerationRequest build() {
            return new KeyGenerationRequest(keyId, type, algorithm, keyBits, usages, tenantId,
                    rotationPolicy, exportable, attributes);
        }
    }
}
package cn.tolim.spissatus4j.contract.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable request presented to every policy rule. The descriptor is present
 * when the operation touches an existing key and lets usage/tenant rules run
 * without loading key material.
 */
public record PolicyRequest(
        AlgorithmId algorithm,
        Operation operation,
        KeyId keyId,
        KeyVersion keyVersion,
        KeyDescriptor key,
        CallerContext caller,
        Map<String, String> attributes) {

    public PolicyRequest {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(caller, "caller");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    public static PolicyRequest of(Operation operation, CallerContext caller) {
        return new PolicyRequest(null, operation, null, null, null, caller, Map.of());
    }

    public static Builder builder(Operation operation, CallerContext caller) {
        return new Builder().operation(operation).caller(caller);
    }

    public static final class Builder {
        private AlgorithmId algorithm;
        private Operation operation;
        private KeyId keyId;
        private KeyVersion keyVersion;
        private KeyDescriptor key;
        private CallerContext caller;
        private Map<String, String> attributes = Map.of();

        public Builder algorithm(AlgorithmId value) {
            this.algorithm = value;
            return this;
        }

        public Builder operation(Operation value) {
            this.operation = value;
            return this;
        }

        public Builder keyId(KeyId value) {
            this.keyId = value;
            return this;
        }

        public Builder keyVersion(KeyVersion value) {
            this.keyVersion = value;
            return this;
        }

        public Builder key(KeyDescriptor value) {
            this.key = value;
            return this;
        }

        public Builder caller(CallerContext value) {
            this.caller = value;
            return this;
        }

        public Builder attributes(Map<String, String> value) {
            this.attributes = value;
            return this;
        }

        public PolicyRequest build() {
            return new PolicyRequest(algorithm, operation, keyId, keyVersion, key, caller, attributes);
        }
    }
}
package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Map;
import java.util.Objects;

/** Request to sign a message with a managed private key. */
public final class SignRequest {

    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final Long keyVersion;
    private final byte[] message;
    private final CallerContext caller;
    private final Map<String, String> attributes;

    private SignRequest(Builder builder) {
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.keyId = Objects.requireNonNull(builder.keyId, "keyId");
        this.keyVersion = builder.keyVersion;
        this.message = Objects.requireNonNull(builder.message, "message").clone();
        this.caller = Objects.requireNonNull(builder.caller, "caller");
        this.attributes = Map.copyOf(Objects.requireNonNull(builder.attributes, "attributes"));
    }

    public static Builder builder(AlgorithmId algorithm, KeyId keyId, byte[] message, CallerContext caller) {
        return new Builder().algorithm(algorithm).keyId(keyId).message(message).caller(caller);
    }

    public AlgorithmId algorithm() {
        return algorithm;
    }

    public KeyId keyId() {
        return keyId;
    }

    public Long keyVersion() {
        return keyVersion;
    }

    public byte[] message() {
        return message.clone();
    }

    public CallerContext caller() {
        return caller;
    }

    public Map<String, String> attributes() {
        return attributes;
    }

    public static final class Builder {
        private AlgorithmId algorithm;
        private KeyId keyId;
        private Long keyVersion;
        private byte[] message = new byte[0];
        private CallerContext caller;
        private Map<String, String> attributes = Map.of();

        public Builder algorithm(AlgorithmId value) {
            this.algorithm = value;
            return this;
        }

        public Builder keyId(KeyId value) {
            this.keyId = value;
            return this;
        }

        public Builder keyVersion(Long value) {
            this.keyVersion = value;
            return this;
        }

        public Builder message(byte[] value) {
            this.message = value;
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

        public SignRequest build() {
            return new SignRequest(this);
        }
    }
}
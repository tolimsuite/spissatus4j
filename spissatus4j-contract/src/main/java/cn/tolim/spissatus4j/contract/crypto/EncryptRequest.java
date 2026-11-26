package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Map;
import java.util.Objects;

/** Request to encrypt data with a managed key. */
public final class EncryptRequest {

    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final Long keyVersion;
    private final byte[] plaintext;
    private final AAD aad;
    private final CallerContext caller;
    private final Map<String, String> attributes;

    private EncryptRequest(Builder builder) {
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.keyId = Objects.requireNonNull(builder.keyId, "keyId");
        this.keyVersion = builder.keyVersion;
        this.plaintext = Objects.requireNonNull(builder.plaintext, "plaintext").clone();
        this.aad = Objects.requireNonNull(builder.aad, "aad");
        this.caller = Objects.requireNonNull(builder.caller, "caller");
        this.attributes = Map.copyOf(Objects.requireNonNull(builder.attributes, "attributes"));
    }

    public static Builder builder(AlgorithmId algorithm, KeyId keyId, byte[] plaintext, CallerContext caller) {
        return new Builder().algorithm(algorithm).keyId(keyId).plaintext(plaintext).caller(caller);
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

    public byte[] plaintext() {
        return plaintext.clone();
    }

    public AAD aad() {
        return aad;
    }

    public CallerContext caller() {
        return caller;
    }

    public Map<String, String> attributes() {
        return attributes;
    }

    @Override
    public String toString() {
        return "EncryptRequest[algorithm=" + algorithm + ", keyId=" + keyId
                + ", plaintextLength=" + plaintext.length + "]";
    }

    public static final class Builder {
        private AlgorithmId algorithm;
        private KeyId keyId;
        private Long keyVersion;
        private byte[] plaintext = new byte[0];
        private AAD aad = AAD.empty();
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

        public Builder plaintext(byte[] value) {
            this.plaintext = value;
            return this;
        }

        public Builder aad(AAD value) {
            this.aad = value;
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

        public EncryptRequest build() {
            return new EncryptRequest(this);
        }
    }
}
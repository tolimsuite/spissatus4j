package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Request to verify a signature. When an explicit {@link PublicKey} is given,
 * the key manager is bypassed; keyId may then be null.
 */
public final class VerifyRequest {

    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final KeyVersion keyVersion;
    private final byte[] message;
    private final byte[] signature;
    private final PublicKey publicKey;
    private final CallerContext caller;

    private VerifyRequest(Builder builder) {
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.keyId = builder.keyId;
        this.keyVersion = builder.keyVersion;
        this.message = Objects.requireNonNull(builder.message, "message").clone();
        this.signature = Objects.requireNonNull(builder.signature, "signature").clone();
        this.publicKey = builder.publicKey;
        this.caller = Objects.requireNonNull(builder.caller, "caller");
        if (keyId == null && publicKey == null) {
            throw new IllegalArgumentException("Either keyId or publicKey is required");
        }
    }

    public static Builder builder(AlgorithmId algorithm, byte[] message, byte[] signature, CallerContext caller) {
        return new Builder().algorithm(algorithm).message(message).signature(signature).caller(caller);
    }

    public AlgorithmId algorithm() {
        return algorithm;
    }

    public KeyId keyId() {
        return keyId;
    }

    public KeyVersion keyVersion() {
        return keyVersion;
    }

    public byte[] message() {
        return message.clone();
    }

    public byte[] signature() {
        return signature.clone();
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public CallerContext caller() {
        return caller;
    }

    public static final class Builder {
        private AlgorithmId algorithm;
        private KeyId keyId;
        private KeyVersion keyVersion;
        private byte[] message = new byte[0];
        private byte[] signature = new byte[0];
        private PublicKey publicKey;
        private CallerContext caller;

        public Builder algorithm(AlgorithmId value) {
            this.algorithm = value;
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

        public Builder message(byte[] value) {
            this.message = value;
            return this;
        }

        public Builder signature(byte[] value) {
            this.signature = value;
            return this;
        }

        public Builder publicKey(PublicKey value) {
            this.publicKey = value;
            return this;
        }

        public Builder caller(CallerContext value) {
            this.caller = value;
            return this;
        }

        public VerifyRequest build() {
            return new VerifyRequest(this);
        }
    }
}
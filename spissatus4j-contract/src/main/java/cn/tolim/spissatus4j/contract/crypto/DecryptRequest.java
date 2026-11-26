package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Objects;

/** Request to decrypt data. Build from {@link EncryptedData} for the common path. */
public final class DecryptRequest {

    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final KeyVersion keyVersion;
    private final Nonce nonce;
    private final byte[] ciphertext;
    private final byte[] tag;
    private final AAD aad;
    private final CallerContext caller;

    private DecryptRequest(Builder builder) {
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.keyId = Objects.requireNonNull(builder.keyId, "keyId");
        this.keyVersion = builder.keyVersion;
        this.nonce = builder.nonce == null ? Nonce.empty() : builder.nonce;
        this.ciphertext = Objects.requireNonNull(builder.ciphertext, "ciphertext").clone();
        this.tag = Objects.requireNonNull(builder.tag, "tag").clone();
        this.aad = Objects.requireNonNull(builder.aad, "aad");
        this.caller = Objects.requireNonNull(builder.caller, "caller");
    }

    public static DecryptRequest from(EncryptedData data, CallerContext caller) {
        Objects.requireNonNull(data, "data");
        return new Builder().algorithm(data.algorithm()).keyId(data.keyId()).keyVersion(data.keyVersion())
                .nonce(data.nonce()).ciphertext(data.ciphertext()).tag(data.tag())
                .aad(data.aad()).caller(caller).build();
    }

    public static Builder builder(AlgorithmId algorithm, KeyId keyId, byte[] ciphertext, CallerContext caller) {
        return new Builder().algorithm(algorithm).keyId(keyId).ciphertext(ciphertext).caller(caller);
    }

    public Builder toBuilder() {
        return new Builder().algorithm(algorithm).keyId(keyId).keyVersion(keyVersion)
                .nonce(nonce).ciphertext(ciphertext).tag(tag).aad(aad).caller(caller);
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

    public Nonce nonce() {
        return nonce;
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public byte[] tag() {
        return tag.clone();
    }

    public AAD aad() {
        return aad;
    }

    public CallerContext caller() {
        return caller;
    }

    @Override
    public String toString() {
        return "DecryptRequest[algorithm=" + algorithm + ", keyId=" + keyId
                + ", ciphertextLength=" + ciphertext.length + "]";
    }

    public static final class Builder {
        private AlgorithmId algorithm;
        private KeyId keyId;
        private KeyVersion keyVersion;
        private Nonce nonce;
        private byte[] ciphertext = new byte[0];
        private byte[] tag = new byte[0];
        private AAD aad = AAD.empty();
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

        public Builder nonce(Nonce value) {
            this.nonce = value;
            return this;
        }

        public Builder ciphertext(byte[] value) {
            this.ciphertext = value;
            return this;
        }

        public Builder tag(byte[] value) {
            this.tag = value;
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

        public DecryptRequest build() {
            return new DecryptRequest(this);
        }
    }
}
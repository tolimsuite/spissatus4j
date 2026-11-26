package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.time.Instant;
import java.util.Objects;

/**
 * Self-contained result of an encryption operation. The ciphertext excludes
 * the nonce and tag; envelopes bundle them for storage or transport.
 */
public final class EncryptedData {

    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final KeyVersion keyVersion;
    private final Nonce nonce;
    private final byte[] ciphertext;
    private final byte[] tag;
    private final AAD aad;
    private final Instant createdAt;

    private EncryptedData(Builder builder) {
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.keyId = Objects.requireNonNull(builder.keyId, "keyId");
        this.keyVersion = Objects.requireNonNull(builder.keyVersion, "keyVersion");
        this.nonce = Objects.requireNonNull(builder.nonce, "nonce");
        this.ciphertext = Objects.requireNonNull(builder.ciphertext, "ciphertext").clone();
        this.tag = Objects.requireNonNull(builder.tag, "tag").clone();
        this.aad = Objects.requireNonNull(builder.aad, "aad");
        this.createdAt = Objects.requireNonNull(builder.createdAt, "createdAt");
    }

    public static Builder builder() {
        return new Builder();
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

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public String toString() {
        return "EncryptedData[algorithm=" + algorithm + ", keyId=" + keyId + ", version=" + keyVersion
                + ", nonceLength=" + nonce.length() + ", ciphertextLength=" + ciphertext.length
                + ", tagLength=" + tag.length + "]";
    }

    public static final class Builder {
        private AlgorithmId algorithm;
        private KeyId keyId;
        private KeyVersion keyVersion;
        private Nonce nonce = Nonce.empty();
        private byte[] ciphertext = new byte[0];
        private byte[] tag = new byte[0];
        private AAD aad = AAD.empty();
        private Instant createdAt = Instant.now();

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

        public Builder createdAt(Instant value) {
            this.createdAt = value;
            return this;
        }

        public EncryptedData build() {
            return new EncryptedData(this);
        }
    }
}
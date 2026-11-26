package cn.tolim.spissatus4j.contract.envelope;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Self-describing ciphertext envelope. Contains no key material, only
 * algorithm and key routing metadata.
 */
public final class Envelope {

    private final int version;
    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final KeyVersion keyVersion;
    private final Nonce nonce;
    private final Salt salt;
    private final KdfParameters kdfParameters;
    private final AAD aad;
    private final byte[] ciphertext;
    private final byte[] tag;
    private final Instant createdAt;
    private final EnvelopeFormat format;
    private final BinaryEncoding binaryEncoding;
    private final Map<String, String> attributes;
    private final byte[] headerHash;

    private Envelope(Builder builder) {
        this.version = builder.version;
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.keyId = Objects.requireNonNull(builder.keyId, "keyId");
        this.keyVersion = Objects.requireNonNull(builder.keyVersion, "keyVersion");
        this.nonce = builder.nonce == null ? Nonce.empty() : builder.nonce;
        this.salt = builder.salt == null ? Salt.empty() : builder.salt;
        this.kdfParameters = builder.kdfParameters;
        this.aad = builder.aad == null ? AAD.empty() : builder.aad;
        this.ciphertext = Objects.requireNonNull(builder.ciphertext, "ciphertext").clone();
        this.tag = Objects.requireNonNull(builder.tag, "tag").clone();
        this.createdAt = Objects.requireNonNull(builder.createdAt, "createdAt");
        this.format = Objects.requireNonNull(builder.format, "format");
        this.binaryEncoding = Objects.requireNonNull(builder.binaryEncoding, "binaryEncoding");
        this.attributes = Map.copyOf(Objects.requireNonNull(builder.attributes, "attributes"));
        this.headerHash = builder.headerHash == null ? new byte[0] : builder.headerHash.clone();
        if (version < 1) {
            throw new IllegalArgumentException("Envelope version must be positive");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public int version() {
        return version;
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

    public Salt salt() {
        return salt;
    }

    public KdfParameters kdfParameters() {
        return kdfParameters;
    }

    public AAD aad() {
        return aad;
    }

    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public byte[] tag() {
        return tag.clone();
    }

    public Instant createdAt() {
        return createdAt;
    }

    public EnvelopeFormat format() {
        return format;
    }

    public BinaryEncoding binaryEncoding() {
        return binaryEncoding;
    }

    public Map<String, String> attributes() {
        return attributes;
    }

    /**
     * SHA-256 metadata binding for v2 envelopes. Empty for v1 envelopes.
     * The value is metadata, never secret.
     */
    public byte[] headerHash() {
        return headerHash.clone();
    }

    public Envelope withEncoding(EnvelopeFormat newFormat, BinaryEncoding newEncoding) {
        return toBuilder().format(newFormat).binaryEncoding(newEncoding).build();
    }

    public Builder toBuilder() {
        return new Builder().version(version).algorithm(algorithm).keyId(keyId).keyVersion(keyVersion)
                .nonce(nonce).salt(salt).kdfParameters(kdfParameters).aad(aad)
                .ciphertext(ciphertext).tag(tag).createdAt(createdAt).format(format)
                .binaryEncoding(binaryEncoding).attributes(attributes).headerHash(headerHash);
    }

    @Override
    public String toString() {
        return "Envelope[version=" + version + ", algorithm=" + algorithm + ", keyId=" + keyId
                + ", keyVersion=" + keyVersion + ", format=" + format
                + ", ciphertextLength=" + ciphertext.length + "]";
    }

    public static final class Builder {
        private int version = 1;
        private AlgorithmId algorithm;
        private KeyId keyId;
        private KeyVersion keyVersion;
        private Nonce nonce = Nonce.empty();
        private Salt salt = Salt.empty();
        private KdfParameters kdfParameters;
        private AAD aad = AAD.empty();
        private byte[] ciphertext = new byte[0];
        private byte[] tag = new byte[0];
        private Instant createdAt = Instant.now();
        private EnvelopeFormat format = EnvelopeFormat.JSON;
        private BinaryEncoding binaryEncoding = BinaryEncoding.BASE64;
        private Map<String, String> attributes = Map.of();
        private byte[] headerHash = new byte[0];

        public Builder version(int value) {
            this.version = value;
            return this;
        }

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

        public Builder salt(Salt value) {
            this.salt = value;
            return this;
        }

        public Builder kdfParameters(KdfParameters value) {
            this.kdfParameters = value;
            return this;
        }

        public Builder aad(AAD value) {
            this.aad = value;
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

        public Builder createdAt(Instant value) {
            this.createdAt = value;
            return this;
        }

        public Builder format(EnvelopeFormat value) {
            this.format = value;
            return this;
        }

        public Builder binaryEncoding(BinaryEncoding value) {
            this.binaryEncoding = value;
            return this;
        }

        public Builder attributes(Map<String, String> value) {
            this.attributes = value;
            return this;
        }

        public Builder headerHash(byte[] value) {
            this.headerHash = value;
            return this;
        }

        public Envelope build() {
            return new Envelope(this);
        }
    }
}
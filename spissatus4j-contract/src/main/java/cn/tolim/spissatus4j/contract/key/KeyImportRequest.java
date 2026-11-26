package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Request to import external key material. The material array is copied on
 * construction and on access; the password array is never copied into logs.
 */
public final class KeyImportRequest {

    private final KeyId keyId;
    private final ImportFormat format;
    private final byte[] material;
    private final char[] password;
    private final KeyType type;
    private final AlgorithmId algorithm;
    private final Set<KeyUsage> usages;
    private final String tenantId;
    private final boolean exportable;
    private final Map<String, String> attributes;

    private KeyImportRequest(Builder builder) {
        this.keyId = Objects.requireNonNull(builder.keyId, "keyId");
        this.format = Objects.requireNonNull(builder.format, "format");
        this.material = Objects.requireNonNull(builder.material, "material").clone();
        if (this.material.length == 0) {
            throw new IllegalArgumentException("Imported material must not be empty");
        }
        this.password = builder.password == null ? null : builder.password.clone();
        this.type = Objects.requireNonNull(builder.type, "type");
        this.algorithm = Objects.requireNonNull(builder.algorithm, "algorithm");
        this.usages = Set.copyOf(Objects.requireNonNull(builder.usages, "usages"));
        if (this.usages.isEmpty()) {
            throw new IllegalArgumentException("At least one key usage is required");
        }
        this.tenantId = builder.tenantId == null ? "default" : builder.tenantId;
        if (this.tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        this.exportable = builder.exportable;
        this.attributes = Map.copyOf(Objects.requireNonNull(builder.attributes, "attributes"));
    }

    public KeyId keyId() {
        return keyId;
    }

    public ImportFormat format() {
        return format;
    }

    public byte[] material() {
        return material.clone();
    }

    public char[] password() {
        return password == null ? null : password.clone();
    }

    public KeyType type() {
        return type;
    }

    public AlgorithmId algorithm() {
        return algorithm;
    }

    public Set<KeyUsage> usages() {
        return usages;
    }

    public String tenantId() {
        return tenantId;
    }

    public boolean exportable() {
        return exportable;
    }

    public Map<String, String> attributes() {
        return attributes;
    }

    public static Builder builder(KeyId keyId, ImportFormat format, byte[] material,
                                  KeyType type, AlgorithmId algorithm, Set<KeyUsage> usages) {
        return new Builder().keyId(keyId).format(format).material(material).type(type)
                .algorithm(algorithm).usages(usages);
    }

    @Override
    public String toString() {
        return "KeyImportRequest[keyId=" + keyId + ", format=" + format + ", type=" + type
                + ", algorithm=" + algorithm + ", materialLength=" + material.length + "]";
    }

    public static final class Builder {
        private KeyId keyId;
        private ImportFormat format;
        private byte[] material;
        private char[] password;
        private KeyType type;
        private AlgorithmId algorithm;
        private Set<KeyUsage> usages = Set.of();
        private String tenantId = "default";
        private boolean exportable;
        private Map<String, String> attributes = Map.of();

        public Builder keyId(KeyId value) {
            this.keyId = value;
            return this;
        }

        public Builder format(ImportFormat value) {
            this.format = value;
            return this;
        }

        public Builder material(byte[] value) {
            this.material = value;
            return this;
        }

        public Builder password(char[] value) {
            this.password = value;
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

        public Builder usages(Set<KeyUsage> value) {
            this.usages = value;
            return this;
        }

        public Builder tenantId(String value) {
            this.tenantId = value;
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

        public KeyImportRequest build() {
            return new KeyImportRequest(this);
        }
    }
}
package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Request for the unified encryption entry point.
 *
 * <p>Selection intent is mutually exclusive: an exact algorithm, an exact
 * suite, an ordered candidate list, or a profile. The profile is applied only
 * when the caller supplied no explicit selection intent.</p>
 */
public final class UnifiedEncryptRequest {

    private final KeyId keyId;
    private final List<KeyId> candidateKeyIds;
    private final Long keyVersion;
    private final byte[] plaintext;
    private final AAD aad;
    private final CallerContext caller;
    private final AlgorithmId algorithm;
    private final AlgorithmSuite suite;
    private final List<AlgorithmId> candidates;
    private final SelectionProfile profile;
    private final boolean allowDeprecated;
    private final boolean allowExperimental;
    private final boolean allowFamilyReuse;
    private final EnvelopeFormat format;
    private final BinaryEncoding encoding;
    private final Map<String, String> attributes;

    private UnifiedEncryptRequest(Builder builder) {
        this.keyId = builder.keyId;
        this.candidateKeyIds = List.copyOf(builder.candidateKeyIds);
        this.keyVersion = builder.keyVersion;
        this.plaintext = builder.plaintext.clone();
        this.aad = builder.aad;
        this.caller = builder.caller;
        this.algorithm = builder.algorithm;
        this.suite = builder.suite;
        this.candidates = List.copyOf(builder.candidates);
        this.profile = builder.profile;
        this.allowDeprecated = builder.allowDeprecated;
        this.allowExperimental = builder.allowExperimental;
        this.allowFamilyReuse = builder.allowFamilyReuse;
        this.format = builder.format;
        this.encoding = builder.encoding;
        this.attributes = Map.copyOf(builder.attributes);
    }

    public static Builder builder(KeyId keyId, byte[] plaintext, CallerContext caller) {
        return new Builder().keyId(keyId).plaintext(plaintext).caller(caller);
    }

    public static Builder builder(List<KeyId> candidateKeyIds, byte[] plaintext,
                                  CallerContext caller) {
        return new Builder().candidateKeyIds(candidateKeyIds).plaintext(plaintext).caller(caller);
    }

    public KeyId keyId() {
        return keyId;
    }

    public List<KeyId> candidateKeyIds() {
        return candidateKeyIds;
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

    public AlgorithmId algorithm() {
        return algorithm;
    }

    public AlgorithmSuite suite() {
        return suite;
    }

    public List<AlgorithmId> candidates() {
        return candidates;
    }

    public SelectionProfile profile() {
        return profile;
    }

    public boolean allowDeprecated() {
        return allowDeprecated;
    }

    public boolean allowExperimental() {
        return allowExperimental;
    }

    public boolean allowFamilyReuse() {
        return allowFamilyReuse;
    }

    public EnvelopeFormat format() {
        return format;
    }

    public BinaryEncoding encoding() {
        return encoding;
    }

    public Map<String, String> attributes() {
        return attributes;
    }

    @Override
    public String toString() {
        return "UnifiedEncryptRequest[keyId=" + keyId
                + ", candidateKeys=" + candidateKeyIds.size()
                + ", algorithm=" + algorithm
                + ", suite=" + (suite == null ? "none" : suite.id())
                + ", candidates=" + candidates.size()
                + ", profile=" + profile
                + ", plaintextLength=" + plaintext.length
                + ", aadLength=" + aad.length()
                + ", attributes=" + attributes.size() + "]";
    }

    public static final class Builder {

        private KeyId keyId;
        private List<KeyId> candidateKeyIds = List.of();
        private Long keyVersion;
        private byte[] plaintext;
        private AAD aad = AAD.empty();
        private CallerContext caller;
        private AlgorithmId algorithm;
        private AlgorithmSuite suite;
        private List<AlgorithmId> candidates = List.of();
        private SelectionProfile profile;
        private boolean allowDeprecated;
        private boolean allowExperimental;
        private boolean allowFamilyReuse;
        private EnvelopeFormat format = EnvelopeFormat.JSON;
        private BinaryEncoding encoding = BinaryEncoding.BASE64;
        private Map<String, String> attributes = Map.of();

        private Builder() {
        }

        public Builder keyId(KeyId value) {
            this.keyId = value;
            return this;
        }

        public Builder candidateKeyIds(List<KeyId> value) {
            this.candidateKeyIds = value == null ? List.of() : List.copyOf(value);
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

        public Builder algorithm(AlgorithmId value) {
            this.algorithm = value;
            return this;
        }

        public Builder suite(AlgorithmSuite value) {
            this.suite = value;
            return this;
        }

        public Builder candidates(List<AlgorithmId> value) {
            this.candidates = value == null ? List.of() : List.copyOf(value);
            return this;
        }

        public Builder profile(SelectionProfile value) {
            this.profile = value;
            return this;
        }

        public Builder allowDeprecated(boolean value) {
            this.allowDeprecated = value;
            return this;
        }

        public Builder allowExperimental(boolean value) {
            this.allowExperimental = value;
            return this;
        }

        public Builder allowFamilyReuse(boolean value) {
            this.allowFamilyReuse = value;
            return this;
        }

        public Builder format(EnvelopeFormat value) {
            this.format = value;
            return this;
        }

        public Builder encoding(BinaryEncoding value) {
            this.encoding = value;
            return this;
        }

        public Builder attributes(Map<String, String> value) {
            this.attributes = value == null ? Map.of() : Map.copyOf(value);
            return this;
        }

        public UnifiedEncryptRequest build() {
            Objects.requireNonNull(plaintext, "plaintext");
            UnifiedLimits.requirePlaintext(plaintext);
            Objects.requireNonNull(caller, "caller");
            Objects.requireNonNull(aad, "aad");
            UnifiedLimits.requireAad(aad);
            Objects.requireNonNull(format, "format");
            Objects.requireNonNull(encoding, "encoding");
            UnifiedLimits.requireAttributes(attributes);
            if (keyVersion != null && keyVersion < 1) {
                throw new IllegalArgumentException("keyVersion must be positive");
            }

            boolean hasKey = keyId != null;
            boolean hasCandidates = !candidateKeyIds.isEmpty();
            if (hasKey == hasCandidates) {
                throw new IllegalArgumentException(
                        "Exactly one of keyId or candidateKeyIds is required");
            }
            if (hasCandidates) {
                LinkedHashSet<KeyId> unique = new LinkedHashSet<>(candidateKeyIds);
                if (unique.size() != candidateKeyIds.size()) {
                    throw new IllegalArgumentException("candidateKeyIds must not contain duplicates");
                }
                if (unique.size() > UnifiedLimits.MAX_CANDIDATES) {
                    throw new IllegalArgumentException("Too many candidate keys");
                }
                for (KeyId candidate : unique) {
                    Objects.requireNonNull(candidate, "candidateKeyIds");
                }
            }

            int intents = (algorithm == null ? 0 : 1)
                    + (suite == null ? 0 : 1)
                    + (candidates.isEmpty() ? 0 : 1);
            if (intents > 1) {
                throw new IllegalArgumentException(
                        "algorithm, suite and candidates are mutually exclusive");
            }
            if (intents > 0 && profile != null) {
                throw new IllegalArgumentException(
                        "profile cannot be combined with an explicit selection intent");
            }
            if (candidates != null && !candidates.isEmpty()) {
                LinkedHashSet<AlgorithmId> unique = new LinkedHashSet<>(candidates);
                if (unique.size() != candidates.size()) {
                    throw new IllegalArgumentException("candidates must not contain duplicates");
                }
                if (unique.size() > UnifiedLimits.MAX_CANDIDATES) {
                    throw new IllegalArgumentException("Too many candidate algorithms");
                }
            }
            return new UnifiedEncryptRequest(this);
        }
    }
}
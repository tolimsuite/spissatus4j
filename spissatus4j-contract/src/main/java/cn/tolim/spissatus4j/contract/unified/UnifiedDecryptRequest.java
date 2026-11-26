package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/** Request for the unified decryption entry point. */
public final class UnifiedDecryptRequest {

    private final byte[] encodedEnvelope;
    private final String encodedText;
    private final BinaryEncoding encoding;
    private final EnvelopeFormat formatHint;
    private final CallerContext caller;
    private final AlgorithmId expectedAlgorithm;
    private final KeyId expectedKeyId;
    private final Long expectedKeyVersion;
    private final AAD expectedAad;
    private final Map<String, String> expectedAttributes;
    private final Duration maxAge;
    private final boolean allowLegacyV1;

    private UnifiedDecryptRequest(Builder builder) {
        this.encodedEnvelope = builder.encodedEnvelope == null ? null : builder.encodedEnvelope.clone();
        this.encodedText = builder.encodedText;
        this.encoding = builder.encoding;
        this.formatHint = builder.formatHint;
        this.caller = builder.caller;
        this.expectedAlgorithm = builder.expectedAlgorithm;
        this.expectedKeyId = builder.expectedKeyId;
        this.expectedKeyVersion = builder.expectedKeyVersion;
        this.expectedAad = builder.expectedAad;
        this.expectedAttributes = Map.copyOf(builder.expectedAttributes);
        this.maxAge = builder.maxAge;
        this.allowLegacyV1 = builder.allowLegacyV1;
    }

    public static Builder builder(byte[] encodedEnvelope, CallerContext caller) {
        return new Builder().encodedEnvelope(encodedEnvelope).caller(caller);
    }

    public static Builder builder(String encodedText, CallerContext caller) {
        return new Builder().encodedText(encodedText).caller(caller);
    }

    public byte[] encodedEnvelope() {
        return encodedEnvelope == null ? null : encodedEnvelope.clone();
    }

    public String encodedText() {
        return encodedText;
    }

    public BinaryEncoding encoding() {
        return encoding;
    }

    public EnvelopeFormat formatHint() {
        return formatHint;
    }

    public CallerContext caller() {
        return caller;
    }

    public AlgorithmId expectedAlgorithm() {
        return expectedAlgorithm;
    }

    public KeyId expectedKeyId() {
        return expectedKeyId;
    }

    public Long expectedKeyVersion() {
        return expectedKeyVersion;
    }

    public AAD expectedAad() {
        return expectedAad;
    }

    public Map<String, String> expectedAttributes() {
        return expectedAttributes;
    }

    public Duration maxAge() {
        return maxAge;
    }

    public boolean allowLegacyV1() {
        return allowLegacyV1;
    }

    @Override
    public String toString() {
        return "UnifiedDecryptRequest[bytes=" + (encodedEnvelope == null ? 0 : encodedEnvelope.length)
                + ", textLength=" + (encodedText == null ? 0 : encodedText.length())
                + ", encoding=" + encoding + ", formatHint=" + formatHint
                + ", expectedAlgorithm=" + expectedAlgorithm
                + ", expectedKeyId=" + expectedKeyId
                + ", maxAge=" + maxAge + ", allowLegacyV1=" + allowLegacyV1 + "]";
    }

    public static final class Builder {

        private byte[] encodedEnvelope;
        private String encodedText;
        private BinaryEncoding encoding;
        private EnvelopeFormat formatHint;
        private CallerContext caller;
        private AlgorithmId expectedAlgorithm;
        private KeyId expectedKeyId;
        private Long expectedKeyVersion;
        private AAD expectedAad;
        private Map<String, String> expectedAttributes = Map.of();
        private Duration maxAge;
        private boolean allowLegacyV1;

        private Builder() {
        }

        public Builder encodedEnvelope(byte[] value) {
            this.encodedEnvelope = value;
            this.encodedText = null;
            return this;
        }

        public Builder encodedText(String value) {
            this.encodedText = value;
            this.encodedEnvelope = null;
            return this;
        }

        public Builder encoding(BinaryEncoding value) {
            this.encoding = value;
            return this;
        }

        public Builder formatHint(EnvelopeFormat value) {
            this.formatHint = value;
            return this;
        }

        public Builder caller(CallerContext value) {
            this.caller = value;
            return this;
        }

        public Builder expectedAlgorithm(AlgorithmId value) {
            this.expectedAlgorithm = value;
            return this;
        }

        public Builder expectedKeyId(KeyId value) {
            this.expectedKeyId = value;
            return this;
        }

        public Builder expectedKeyVersion(Long value) {
            this.expectedKeyVersion = value;
            return this;
        }

        public Builder expectedAad(AAD value) {
            this.expectedAad = value;
            return this;
        }

        public Builder expectedAttributes(Map<String, String> value) {
            this.expectedAttributes = value == null ? Map.of() : Map.copyOf(value);
            return this;
        }

        public Builder maxAge(Duration value) {
            this.maxAge = value;
            return this;
        }

        public Builder allowLegacyV1(boolean value) {
            this.allowLegacyV1 = value;
            return this;
        }

        public UnifiedDecryptRequest build() {
            boolean hasBytes = encodedEnvelope != null;
            boolean hasText = encodedText != null;
            if (hasBytes == hasText) {
                throw new IllegalArgumentException(
                        "Exactly one of encodedEnvelope or encodedText is required");
            }
            Objects.requireNonNull(caller, "caller");
            if (hasBytes) {
                if (encodedEnvelope.length == 0) {
                    throw new IllegalArgumentException("encodedEnvelope must not be empty");
                }
                if (encoding != null && encoding != BinaryEncoding.RAW) {
                    throw new IllegalArgumentException(
                            "encoding must be RAW or omitted for binary envelopes");
                }
            } else {
                if (encodedText.isEmpty()) {
                    throw new IllegalArgumentException("encodedText must not be empty");
                }
                if (encoding == BinaryEncoding.RAW) {
                    throw new IllegalArgumentException("encodedText cannot use RAW encoding");
                }
            }
            if (expectedKeyVersion != null && expectedKeyVersion < 1) {
                throw new IllegalArgumentException("expectedKeyVersion must be positive");
            }
            if (expectedAad != null) {
                UnifiedLimits.requireAad(expectedAad);
            }
            UnifiedLimits.requireAttributes(expectedAttributes);
            if (maxAge != null && (maxAge.isZero() || maxAge.isNegative())) {
                throw new IllegalArgumentException("maxAge must be positive");
            }
            return new UnifiedDecryptRequest(this);
        }
    }

    /** Convenience for callers that hold the canonical UTF-8 envelope bytes. */
    public byte[] encodedTextBytes() {
        return encodedText == null ? null : encodedText.getBytes(StandardCharsets.UTF_8);
    }
}
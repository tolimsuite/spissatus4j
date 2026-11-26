package cn.tolim.spissatus4j.envelope.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.envelope.VersionPolicy;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.envelope.codec.JsonEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.codec.TlvEnvelopeCodec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Default {@link EnvelopeService} implementation. Codecs are selected by
 * format identifier; decoding sniffs candidate codecs, parses strictly and
 * validates the result before returning it.
 */
public final class DefaultEnvelopeService implements EnvelopeService {

    private final List<EnvelopeCodec> codecs;
    private final VersionPolicy versionPolicy;
    private final int maxBytes;

    public DefaultEnvelopeService() {
        this(defaultCodecs(EnvelopeLimits.DEFAULT_MAX_BYTES), new DefaultVersionPolicy(),
                EnvelopeLimits.DEFAULT_MAX_BYTES);
    }

    public DefaultEnvelopeService(List<EnvelopeCodec> codecs, VersionPolicy versionPolicy) {
        this(codecs, versionPolicy, EnvelopeLimits.DEFAULT_MAX_BYTES);
    }

    public DefaultEnvelopeService(List<EnvelopeCodec> codecs, VersionPolicy versionPolicy, int maxBytes) {
        if (codecs == null) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID, "Envelope codec list is required");
        }
        if (versionPolicy == null) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID, "Envelope version policy is required");
        }
        if (maxBytes < 1) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Maximum envelope size must be positive");
        }
        List<EnvelopeCodec> copy = new ArrayList<>();
        Set<String> formatIds = new HashSet<>();
        for (EnvelopeCodec codec : codecs) {
            if (codec == null) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Envelope codec list must not contain null");
            }
            String formatId;
            try {
                formatId = codec.formatId();
            } catch (RuntimeException e) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Envelope codec has an invalid format identifier");
            }
            if (formatId == null || formatId.isBlank()) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Envelope codec has an invalid format identifier");
            }
            if (!formatIds.add(formatId.toLowerCase(Locale.ROOT))) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Duplicate envelope codec format identifier");
            }
            copy.add(codec);
        }
        this.codecs = List.copyOf(copy);
        this.versionPolicy = versionPolicy;
        this.maxBytes = maxBytes;
    }

    private static List<EnvelopeCodec> defaultCodecs(int maxBytes) {
        return List.of(new TlvEnvelopeCodec(maxBytes), new JsonEnvelopeCodec(maxBytes));
    }

    @Override
    public Envelope create(EncryptedData data, Map<String, String> attributes) {
        if (data == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Encrypted data is required");
        }
        Map<String, String> attributeCopy;
        if (attributes == null) {
            attributeCopy = Map.of();
        } else {
            try {
                attributeCopy = Map.copyOf(attributes);
            } catch (RuntimeException e) {
                throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Invalid envelope attributes");
            }
        }
        return Envelope.builder()
                .version(1)
                .algorithm(data.algorithm())
                .keyId(data.keyId())
                .keyVersion(data.keyVersion())
                .nonce(data.nonce())
                .ciphertext(data.ciphertext())
                .tag(data.tag())
                .aad(data.aad())
                .createdAt(data.createdAt())
                .format(EnvelopeFormat.JSON)
                .binaryEncoding(BinaryEncoding.BASE64)
                .attributes(attributeCopy)
                .build();
    }

    @Override
    public byte[] encode(Envelope envelope, EnvelopeFormat format) {
        if (format == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Envelope format is required");
        }
        validate(envelope);
        EnvelopeCodec codec = codecFor(format);
        if (codec == null) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE,
                    "No envelope codec is registered for the requested format");
        }
        byte[] encoded;
        try {
            encoded = codec.encode(envelope);
        } catch (EnvelopeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE, "Envelope encoding failed");
        }
        if (encoded == null) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE, "Envelope codec produced no output");
        }
        if (encoded.length > maxBytes) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Encoded envelope exceeds the maximum size");
        }
        return encoded;
    }

    @Override
    public Envelope decode(byte[] encoded) {
        if (encoded == null) {
            throw malformed("Envelope bytes are required");
        }
        if (encoded.length > maxBytes) {
            throw malformed("Envelope exceeds the maximum size");
        }
        EnvelopeException failure = null;
        for (EnvelopeCodec codec : codecs) {
            boolean matches;
            try {
                matches = codec.sniff(encoded);
            } catch (RuntimeException e) {
                matches = false;
            }
            if (!matches) {
                continue;
            }
            try {
                Envelope envelope = codec.decode(encoded);
                validate(envelope);
                return envelope;
            } catch (EnvelopeException e) {
                if (failure == null || e.errorCode() == ErrorCode.UNSUPPORTED_ENVELOPE_VERSION) {
                    failure = e;
                }
            } catch (RuntimeException e) {
                if (failure == null) {
                    failure = malformed("Envelope decoding failed");
                }
            }
        }
        if (failure != null && (failure.errorCode() == ErrorCode.UNSUPPORTED_ENVELOPE_VERSION
                || failure.errorCode() == ErrorCode.ENVELOPE_VALIDATION_FAILED)) {
            throw failure;
        }
        throw malformed("No registered envelope codec could parse the input");
    }

    @Override
    public String encodeText(Envelope envelope, EnvelopeFormat format, BinaryEncoding encoding) {
        if (encoding == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Binary encoding is required");
        }
        if (encoding == BinaryEncoding.RAW) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER,
                    "RAW encoding cannot be represented as text");
        }
        byte[] encoded = encode(envelope, format);
        return switch (encoding) {
            case BASE64 -> java.util.Base64.getEncoder().encodeToString(encoded);
            case BASE64URL -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
            case HEX -> hexEncode(encoded);
            case RAW -> throw new EnvelopeException(ErrorCode.INVALID_PARAMETER,
                    "RAW encoding cannot be represented as text");
        };
    }

    @Override
    public Envelope decodeText(String text) {
        if (text == null || text.isEmpty()) {
            throw malformed("Envelope text is required");
        }
        if ((long) text.length() > 4L * maxBytes + 16L) {
            throw malformed("Envelope text exceeds the maximum size");
        }
        boolean hex = isHex(text);
        long decodedLength = hex ? text.length() / 2L : estimateBase64DecodedLength(text);
        if (decodedLength < 0 || decodedLength > maxBytes) {
            throw malformed("Envelope text exceeds the maximum decoded size");
        }
        byte[] encoded;
        if (hex) {
            encoded = hexDecode(text);
        } else {
            try {
                encoded = java.util.Base64.getUrlDecoder().decode(text);
            } catch (IllegalArgumentException urlError) {
                try {
                    encoded = java.util.Base64.getDecoder().decode(text);
                } catch (IllegalArgumentException standardError) {
                    throw malformed("Envelope text is not valid base64 or hex");
                }
            }
        }
        return decode(encoded);
    }

    @Override
    public void validate(Envelope envelope) {
        if (envelope == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Envelope is required");
        }
        int version = envelope.version();
        boolean supported;
        try {
            supported = versionPolicy.isSupported(version);
        } catch (RuntimeException e) {
            throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                    "Envelope version policy evaluation failed");
        }
        if (!supported) {
            throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                    "Unsupported envelope version: " + version);
        }
        AlgorithmId algorithm = envelope.algorithm();
        if (algorithm == null || !algorithm.isKnown()) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope references an unknown algorithm");
        }
        if (envelope.createdAt() == null) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope creation time is required");
        }
        AlgorithmInfo info = algorithm.info();
        if (info.nonceBytes() > 0 && envelope.nonce().length() != info.nonceBytes()) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope nonce length does not match the algorithm");
        }
        if (info.tagBytes() > 0 && envelope.tag().length != info.tagBytes()) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope tag length does not match the algorithm");
        }
        if (envelope.kdfParameters() != null && envelope.salt().isEmpty()) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Key derivation metadata requires a non-empty salt");
        }
        validateAttributes(envelope.attributes());
        if (estimateSize(envelope) > maxBytes) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope exceeds the maximum size");
        }
    }

    @Override
    public boolean supportsVersion(int version) {
        return versionPolicy.isSupported(version);
    }

    @Override
    public VersionPolicy versionPolicy() {
        return versionPolicy;
    }

    private EnvelopeCodec codecFor(EnvelopeFormat format) {
        String formatId = format.name();
        for (EnvelopeCodec codec : codecs) {
            String candidate;
            try {
                candidate = codec.formatId();
            } catch (RuntimeException e) {
                continue;
            }
            if (candidate != null && candidate.equalsIgnoreCase(formatId)) {
                return codec;
            }
        }
        return null;
    }

    private static void validateAttributes(Map<String, String> attributes) {
        if (attributes == null) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope attributes are required");
        }
        if (attributes.size() > EnvelopeLimits.MAX_ATTRIBUTES) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Too many envelope attributes");
        }
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key == null || value == null) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attributes must not contain null");
            }
            if (!Utf8.isWellFormed(key) || !Utf8.isWellFormed(value)) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attributes must be well-formed Unicode");
            }
            int keyBytes = Utf8.length(key);
            if (keyBytes < 1 || keyBytes > EnvelopeLimits.MAX_ATTRIBUTE_KEY_BYTES) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attribute key length is invalid");
            }
            if (Utf8.length(value) > EnvelopeLimits.MAX_ATTRIBUTE_VALUE_BYTES) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attribute value length is invalid");
            }
        }
    }

    private static long estimateSize(Envelope envelope) {
        // Exact size of the canonical TLV representation: fixed framing bytes
        // plus one entry (6-byte tag/length prefix) per populated header field.
        long size = 23L; // magic(8) + version(2) + hint(1) + three int lengths(12)
        size += 6L + Utf8.length(envelope.algorithm().id());
        size += 6L + Utf8.length(envelope.keyId().value());
        size += 6L + 8L;
        if (envelope.nonce().length() > 0) {
            size += 6L + envelope.nonce().length();
        }
        if (envelope.salt().length() > 0) {
            size += 6L + envelope.salt().length();
        }
        if (envelope.aad().length() > 0) {
            size += 6L + envelope.aad().length();
        }
        size += 6L + 8L;
        if (!envelope.attributes().isEmpty()) {
            size += 6L + 4L;
            for (Map.Entry<String, String> entry : envelope.attributes().entrySet()) {
                size += 8L + Utf8.length(entry.getKey()) + Utf8.length(entry.getValue());
            }
        }
        if (envelope.kdfParameters() != null) {
            try {
                size += 6L + Utf8.length(KdfCodec.canonicalize(envelope.kdfParameters()));
            } catch (RuntimeException e) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope KDF metadata is invalid");
            }
        }
        return size + envelope.ciphertext().length + envelope.tag().length;
    }

    /**
     * Computes the exact decoded size of standard or URL Base64 text without
     * allocating it. Returns {@code -1} when the length cannot encode any
     * valid Base64 payload.
     */
    private static long estimateBase64DecodedLength(String text) {
        int length = text.length();
        int padding = 0;
        if (length > 0 && text.charAt(length - 1) == '=') {
            padding = 1;
            if (length > 1 && text.charAt(length - 2) == '=') {
                padding = 2;
            }
        }
        int effective = length - padding;
        int remainder = effective % 4;
        if (remainder == 1) {
            return -1L;
        }
        long decoded = (effective / 4L) * 3L;
        if (remainder == 2) {
            decoded += 1L;
        } else if (remainder == 3) {
            decoded += 2L;
        }
        return decoded;
    }

    private static boolean isHex(String text) {
        if (text.length() == 0 || (text.length() & 1) != 0) {
            return false;
        }
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            boolean hex = (character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f')
                    || (character >= 'A' && character <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static String hexEncode(byte[] bytes) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] output = new char[bytes.length * 2];
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xFF;
            output[index * 2] = alphabet[value >>> 4];
            output[index * 2 + 1] = alphabet[value & 0x0F];
        }
        return new String(output);
    }

    private static byte[] hexDecode(String text) {
        byte[] output = new byte[text.length() / 2];
        for (int index = 0; index < output.length; index++) {
            int high = Character.digit(text.charAt(index * 2), 16);
            int low = Character.digit(text.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw malformed("Envelope text is not valid hex");
            }
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    private static EnvelopeException malformed(String message) {
        return new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, message);
    }

    @Override
    public String toString() {
        return "DefaultEnvelopeService[codecs=" + codecs.size() + ", maxBytes=" + maxBytes + "]";
    }
}
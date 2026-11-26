package cn.tolim.spissatus4j.envelope.codec;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.envelope.internal.EnvelopeLimits;
import cn.tolim.spissatus4j.envelope.internal.KdfCodec;
import cn.tolim.spissatus4j.envelope.internal.Utf8;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Strict binary TLV envelope codec.
 *
 * <p>Wire layout (big-endian): {@code "SPI4ENV1"} magic, unsigned short
 * version, one format-hint byte ({@code 1} = TLV), int header length, TLV
 * header entries, int ciphertext length, ciphertext, int tag length, tag.
 * Header entries are {@code short tag, int length, bytes} with strictly
 * ascending tags. Tag {@code 10} is reserved and always rejected; tag
 * {@code 11} carries the 32-byte header hash of version 2 envelopes.</p>
 */
public final class TlvEnvelopeCodec implements EnvelopeCodec {

    public static final String FORMAT_ID = "TLV";

    private static final byte[] MAGIC = {'S', 'P', 'I', '4', 'E', 'N', 'V', '1'};
    private static final int FORMAT_HINT_TLV = 1;

    private static final int TAG_ALGORITHM = 1;
    private static final int TAG_KEY_ID = 2;
    private static final int TAG_KEY_VERSION = 3;
    private static final int TAG_NONCE = 4;
    private static final int TAG_SALT = 5;
    private static final int TAG_AAD = 6;
    private static final int TAG_CREATED_AT = 7;
    private static final int TAG_ATTRIBUTES = 8;
    private static final int TAG_KDF = 9;
    private static final int TAG_RESERVED = 10;
    private static final int TAG_HEADER_HASH = 11;

    private static final int MIN_ENVELOPE_BYTES = MAGIC.length + 2 + 1 + 4 + 4 + 4;

    private final int maxBytes;

    public TlvEnvelopeCodec() {
        this(EnvelopeLimits.DEFAULT_MAX_BYTES);
    }

    public TlvEnvelopeCodec(int maxBytes) {
        if (maxBytes < MIN_ENVELOPE_BYTES) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Maximum envelope size is too small for the TLV format");
        }
        this.maxBytes = maxBytes;
    }

    @Override
    public String formatId() {
        return FORMAT_ID;
    }

    @Override
    public byte[] encode(Envelope envelope) {
        if (envelope == null) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "Envelope is required");
        }
        try {
            int version = envelope.version();
            if (version < 1 || version > 0xFFFF) {
                throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                        "Envelope version is not representable in the TLV format");
            }
            byte[] header = encodeHeader(envelope);
            if (header.length > EnvelopeLimits.MAX_HEADER_BYTES) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope header exceeds the maximum size");
            }
            byte[] ciphertext = envelope.ciphertext();
            byte[] tag = envelope.tag();
            long total = (long) MAGIC.length + 2 + 1 + 4 + header.length
                    + 4 + ciphertext.length + 4 + tag.length;
            if (total > maxBytes || total > Integer.MAX_VALUE - 8L) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope exceeds the maximum encoded size");
            }
            ByteArrayOutputStream output = new ByteArrayOutputStream((int) total);
            output.write(MAGIC, 0, MAGIC.length);
            writeShort(output, version);
            output.write(FORMAT_HINT_TLV);
            writeInt(output, header.length);
            output.write(header, 0, header.length);
            writeInt(output, ciphertext.length);
            output.write(ciphertext, 0, ciphertext.length);
            writeInt(output, tag.length);
            output.write(tag, 0, tag.length);
            return output.toByteArray();
        } catch (EnvelopeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE, "Envelope encoding failed");
        }
    }

    @Override
    public Envelope decode(byte[] encoded) {
        if (encoded == null) {
            throw malformed("Envelope bytes are required");
        }
        if (encoded.length < MIN_ENVELOPE_BYTES) {
            throw malformed("Envelope is truncated");
        }
        if (encoded.length > maxBytes) {
            throw malformed("Envelope exceeds the maximum size");
        }
        try {
            return decodeStrict(encoded);
        } catch (EnvelopeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw malformed("Envelope decoding failed");
        }
    }

    @Override
    public boolean sniff(byte[] encoded) {
        if (encoded == null || encoded.length < MAGIC.length) {
            return false;
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (encoded[index] != MAGIC[index]) {
                return false;
            }
        }
        return true;
    }

    private Envelope decodeStrict(byte[] encoded) {
        Cursor cursor = new Cursor(encoded);
        byte[] magic = cursor.readBytes(MAGIC.length);
        if (!MessageDigest.isEqual(magic, MAGIC)) {
            throw malformed("Invalid envelope magic");
        }
        int version = cursor.readUnsignedShort();
        if (version < 1) {
            throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                    "Unsupported envelope version");
        }
        int formatHint = cursor.readUnsignedByte();
        if (formatHint != FORMAT_HINT_TLV) {
            throw malformed("Unsupported TLV format hint");
        }
        int headerLength = cursor.readInt();
        if (headerLength < 0 || headerLength > EnvelopeLimits.MAX_HEADER_BYTES) {
            throw malformed("Invalid header length");
        }
        if (headerLength > cursor.remaining() - 8) {
            throw malformed("Invalid header length");
        }
        int headerEnd = cursor.position() + headerLength;

        byte[] algorithm = null;
        byte[] keyId = null;
        long keyVersion = 0L;
        boolean hasKeyVersion = false;
        byte[] nonce = null;
        byte[] salt = null;
        byte[] aad = null;
        long createdAt = 0L;
        boolean hasCreatedAt = false;
        byte[] attributes = null;
        byte[] kdf = null;
        byte[] headerHash = null;
        int previousTag = 0;

        while (cursor.position() < headerEnd) {
            if (headerEnd - cursor.position() < 6) {
                throw malformed("Truncated header entry");
            }
            int tag = cursor.readUnsignedShort();
            int length = cursor.readInt();
            if (tag <= previousTag) {
                throw malformed("Header tags must be strictly ascending");
            }
            previousTag = tag;
            if (tag < TAG_ALGORITHM || tag > TAG_HEADER_HASH) {
                throw malformed("Unknown header tag");
            }
            if (length < 0 || length > headerEnd - cursor.position()) {
                throw malformed("Invalid header entry length");
            }
            byte[] value = cursor.readBytes(length);
            switch (tag) {
                case TAG_ALGORITHM -> algorithm = value;
                case TAG_KEY_ID -> keyId = value;
                case TAG_KEY_VERSION -> {
                    if (length != 8) {
                        throw malformed("Invalid key version length");
                    }
                    keyVersion = longFromBytes(value);
                    hasKeyVersion = true;
                }
                case TAG_NONCE -> nonce = value;
                case TAG_SALT -> salt = value;
                case TAG_AAD -> aad = value;
                case TAG_CREATED_AT -> {
                    if (length != 8) {
                        throw malformed("Invalid creation time length");
                    }
                    createdAt = longFromBytes(value);
                    hasCreatedAt = true;
                }
                case TAG_ATTRIBUTES -> attributes = value;
                case TAG_KDF -> kdf = value;
                case TAG_RESERVED -> throw malformed("Reserved header tag is not allowed");
                case TAG_HEADER_HASH -> {
                    if (version == 1) {
                        throw malformed("Version 1 envelopes must not carry a header hash");
                    }
                    if (length != EnvelopeLimits.MAX_HEADER_HASH_BYTES) {
                        throw malformed("Invalid header hash length");
                    }
                    headerHash = value;
                }
                default -> throw malformed("Unknown header tag");
            }
        }
        if (cursor.position() != headerEnd) {
            throw malformed("Invalid header length");
        }
        if (algorithm == null || keyId == null || !hasKeyVersion || !hasCreatedAt) {
            throw malformed("Missing required header entry");
        }
        if (version == 2 && headerHash == null) {
            throw malformed("Version 2 envelopes require a header hash");
        }

        int ciphertextLength = cursor.readInt();
        if (ciphertextLength < 0 || ciphertextLength > cursor.remaining() - 4) {
            throw malformed("Invalid ciphertext length");
        }
        byte[] ciphertext = cursor.readBytes(ciphertextLength);
        int tagLength = cursor.readInt();
        if (tagLength < 0 || tagLength > cursor.remaining()) {
            throw malformed("Invalid tag length");
        }
        byte[] authenticationTag = cursor.readBytes(tagLength);
        if (cursor.remaining() != 0) {
            throw malformed("Trailing bytes after envelope");
        }

        Envelope.Builder builder = Envelope.builder()
                .version(version)
                .algorithm(parseAlgorithm(algorithm))
                .keyId(parseKeyId(keyId))
                .keyVersion(KeyVersion.of(keyVersion))
                .nonce(nonce == null ? Nonce.empty() : Nonce.of(nonce))
                .salt(salt == null ? Salt.empty() : Salt.of(salt))
                .aad(aad == null ? AAD.empty() : AAD.of(aad))
                .ciphertext(ciphertext)
                .tag(authenticationTag)
                .createdAt(Instant.ofEpochMilli(createdAt))
                .format(EnvelopeFormat.TLV)
                .binaryEncoding(BinaryEncoding.RAW)
                .attributes(attributes == null ? Map.of() : decodeAttributes(attributes))
                .headerHash(headerHash == null ? new byte[0] : headerHash);
        if (kdf != null) {
            builder.kdfParameters(KdfCodec.fromCanonical(Utf8.decode(kdf)));
        }
        return builder.build();
    }

    private static byte[] encodeHeader(Envelope envelope) {
        ByteArrayOutputStream header = new ByteArrayOutputStream(192);
        writeEntry(header, TAG_ALGORITHM, Utf8.encode(envelope.algorithm().id()));
        writeEntry(header, TAG_KEY_ID, Utf8.encode(envelope.keyId().value()));
        writeEntry(header, TAG_KEY_VERSION, longToBytes(envelope.keyVersion().value()));
        if (envelope.nonce().length() > 0) {
            writeEntry(header, TAG_NONCE, envelope.nonce().asBytes());
        }
        if (envelope.salt().length() > 0) {
            writeEntry(header, TAG_SALT, envelope.salt().asBytes());
        }
        if (envelope.aad().length() > 0) {
            writeEntry(header, TAG_AAD, envelope.aad().asBytes());
        }
        writeEntry(header, TAG_CREATED_AT, longToBytes(envelope.createdAt().toEpochMilli()));
        if (!envelope.attributes().isEmpty()) {
            writeEntry(header, TAG_ATTRIBUTES, encodeAttributes(envelope.attributes()));
        }
        if (envelope.kdfParameters() != null) {
            writeEntry(header, TAG_KDF, Utf8.encode(KdfCodec.canonicalize(envelope.kdfParameters())));
        }
        if (envelope.version() >= 2) {
            writeEntry(header, TAG_HEADER_HASH, envelope.headerHash());
        }
        return header.toByteArray();
    }

    private static byte[] encodeAttributes(Map<String, String> attributes) {
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (!Utf8.isWellFormed(entry.getKey()) || !Utf8.isWellFormed(entry.getValue())) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attributes must be well-formed Unicode");
            }
        }
        if (attributes.size() > EnvelopeLimits.MAX_ATTRIBUTES) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Too many envelope attributes");
        }
        TreeMap<String, String> sorted = new TreeMap<>();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key == null || value == null) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attributes must not contain null");
            }
            byte[] keyBytes = Utf8.encode(key);
            int valueBytes = Utf8.length(value);
            if (keyBytes.length < 1 || keyBytes.length > EnvelopeLimits.MAX_ATTRIBUTE_KEY_BYTES
                    || valueBytes > EnvelopeLimits.MAX_ATTRIBUTE_VALUE_BYTES) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope attribute length is invalid");
            }
            sorted.put(key, value);
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(128);
        writeInt(output, sorted.size());
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            byte[] keyBytes = Utf8.encode(entry.getKey());
            byte[] valueBytes = Utf8.encode(entry.getValue());
            writeInt(output, keyBytes.length);
            output.write(keyBytes, 0, keyBytes.length);
            writeInt(output, valueBytes.length);
            output.write(valueBytes, 0, valueBytes.length);
        }
        return output.toByteArray();
    }

    private static Map<String, String> decodeAttributes(byte[] encoded) {
        Cursor cursor = new Cursor(encoded);
        int count = cursor.readInt();
        if (count < 0 || count > EnvelopeLimits.MAX_ATTRIBUTES) {
            throw malformed("Invalid attribute count");
        }
        Map<String, String> attributes = new LinkedHashMap<>(Math.max(1, count * 2));
        String previousKey = null;
        for (int index = 0; index < count; index++) {
            int keyLength = cursor.readInt();
            if (keyLength < 1 || keyLength > EnvelopeLimits.MAX_ATTRIBUTE_KEY_BYTES) {
                throw malformed("Invalid attribute key length");
            }
            String key = Utf8.decode(cursor.readBytes(keyLength));
            int valueLength = cursor.readInt();
            if (valueLength < 0 || valueLength > EnvelopeLimits.MAX_ATTRIBUTE_VALUE_BYTES) {
                throw malformed("Invalid attribute value length");
            }
            String value = Utf8.decode(cursor.readBytes(valueLength));
            if (previousKey != null && key.compareTo(previousKey) <= 0) {
                throw malformed("Attributes must be strictly sorted");
            }
            previousKey = key;
            attributes.put(key, value);
        }
        if (cursor.remaining() != 0) {
            throw malformed("Trailing bytes in attribute block");
        }
        return attributes;
    }

    private static AlgorithmId parseAlgorithm(byte[] encoded) {
        String text = Utf8.decode(encoded);
        if (text.isEmpty()) {
            throw malformed("Missing algorithm identifier");
        }
        try {
            return AlgorithmId.of(text);
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid algorithm identifier");
        }
    }

    private static KeyId parseKeyId(byte[] encoded) {
        String text = Utf8.decode(encoded);
        if (text.isEmpty()) {
            throw malformed("Missing key identifier");
        }
        try {
            return KeyId.of(text);
        } catch (IllegalArgumentException e) {
            throw malformed("Invalid key identifier");
        }
    }

    private static void writeEntry(ByteArrayOutputStream output, int tag, byte[] value) {
        writeShort(output, tag);
        writeInt(output, value.length);
        output.write(value, 0, value.length);
    }

    private static void writeShort(ByteArrayOutputStream output, int value) {
        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream output, int value) {
        output.write((value >>> 24) & 0xFF);
        output.write((value >>> 16) & 0xFF);
        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static byte[] longToBytes(long value) {
        return new byte[]{
                (byte) (value >>> 56), (byte) (value >>> 48),
                (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value
        };
    }

    private static long longFromBytes(byte[] value) {
        long result = 0L;
        for (int index = 0; index < 8; index++) {
            result = (result << 8) | (value[index] & 0xFFL);
        }
        return result;
    }

    private static EnvelopeException malformed(String message) {
        return new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, message);
    }

    private static final class Cursor {

        private final byte[] data;
        private int position;

        private Cursor(byte[] data) {
            this.data = data;
        }

        private int position() {
            return position;
        }

        private int remaining() {
            return data.length - position;
        }

        private int readUnsignedByte() {
            require(1);
            return data[position++] & 0xFF;
        }

        private int readUnsignedShort() {
            require(2);
            int result = ((data[position] & 0xFF) << 8) | (data[position + 1] & 0xFF);
            position += 2;
            return result;
        }

        private int readInt() {
            require(4);
            int result = ((data[position] & 0xFF) << 24)
                    | ((data[position + 1] & 0xFF) << 16)
                    | ((data[position + 2] & 0xFF) << 8)
                    | (data[position + 3] & 0xFF);
            position += 4;
            return result;
        }

        private byte[] readBytes(int length) {
            require(length);
            byte[] result = new byte[length];
            System.arraycopy(data, position, result, 0, length);
            position += length;
            return result;
        }

        private void require(int length) {
            if (length < 0 || length > data.length - position) {
                throw malformed("Envelope is truncated");
            }
        }
    }
}
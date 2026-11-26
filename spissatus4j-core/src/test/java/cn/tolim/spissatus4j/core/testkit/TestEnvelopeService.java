package cn.tolim.spissatus4j.core.testkit;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.envelope.VersionPolicy;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/** Minimal v1/v2 envelope service for core tests (not a production codec). */
public final class TestEnvelopeService implements EnvelopeService {

    private static final byte[] MAGIC = {'T', 'E', 'S', 'T', 'E', 'N', 'V', '1'};

    private final VersionPolicy versionPolicy = new VersionPolicy() {
        @Override
        public int currentVersion() {
            return 2;
        }

        @Override
        public boolean isSupported(int version) {
            return version == 1 || version == 2;
        }

        @Override
        public String migrationHint(int fromVersion) {
            return fromVersion == 1 ? "Recreate as v2 with the unified API" : "Current version";
        }
    };

    @Override
    public Envelope create(EncryptedData data, Map<String, String> attributes) {
        return base(data, attributes, 1, new byte[0]);
    }

    @Override
    public Envelope createBound(EncryptedData data, byte[] headerHash,
                                Map<String, String> attributes) {
        return base(data, attributes, 2, headerHash);
    }

    private static Envelope base(EncryptedData data, Map<String, String> attributes,
                                 int version, byte[] headerHash) {
        return Envelope.builder()
                .version(version)
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
                .attributes(attributes == null ? Map.of() : attributes)
                .headerHash(headerHash)
                .build();
    }

    @Override
    public byte[] encode(Envelope envelope, EnvelopeFormat format) {
        validate(envelope);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.write(MAGIC);
                output.writeInt(envelope.version());
                output.writeUTF(envelope.algorithm().id());
                output.writeUTF(envelope.keyId().value());
                output.writeLong(envelope.keyVersion().value());
                writeBytes(output, envelope.nonce().asBytes());
                writeBytes(output, envelope.salt().asBytes());
                writeBytes(output, envelope.aad().asBytes());
                writeBytes(output, envelope.ciphertext());
                writeBytes(output, envelope.tag());
                output.writeLong(envelope.createdAt().toEpochMilli());
                writeBytes(output, envelope.headerHash());
                output.writeUTF(envelope.format().name());
                output.writeUTF(envelope.binaryEncoding().name());
                Map<String, String> sorted = new TreeMap<>(envelope.attributes());
                output.writeInt(sorted.size());
                for (Map.Entry<String, String> entry : sorted.entrySet()) {
                    output.writeUTF(entry.getKey());
                    output.writeUTF(entry.getValue());
                }
            }
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_CODEC_FAILURE, "Test encode failed");
        }
    }

    @Override
    public String encodeText(Envelope envelope, EnvelopeFormat format, BinaryEncoding encoding) {
        if (encoding == BinaryEncoding.RAW) {
            throw new EnvelopeException(ErrorCode.INVALID_PARAMETER, "RAW is not text");
        }
        return Base64.getEncoder().encodeToString(encode(envelope, format));
    }

    @Override
    public Envelope decode(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, "Missing envelope");
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            byte[] magic = input.readNBytes(MAGIC.length);
            if (!java.util.Arrays.equals(magic, MAGIC)) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, "Bad test envelope");
            }
            int version = input.readInt();
            AlgorithmId algorithm = AlgorithmId.of(input.readUTF());
            KeyId keyId = KeyId.of(input.readUTF());
            KeyVersion keyVersion = KeyVersion.of(input.readLong());
            Nonce nonce = Nonce.of(readBytes(input));
            Salt salt = Salt.of(readBytes(input));
            AAD aad = AAD.of(readBytes(input));
            byte[] ciphertext = readBytes(input);
            byte[] tag = readBytes(input);
            Instant createdAt = Instant.ofEpochMilli(input.readLong());
            byte[] headerHash = readBytes(input);
            EnvelopeFormat format = EnvelopeFormat.valueOf(input.readUTF());
            BinaryEncoding encoding = BinaryEncoding.valueOf(input.readUTF());
            int attributeCount = input.readInt();
            if (attributeCount < 0 || attributeCount > 64) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, "Bad attribute count");
            }
            Map<String, String> attributes = new LinkedHashMap<>();
            for (int index = 0; index < attributeCount; index++) {
                attributes.put(input.readUTF(), input.readUTF());
            }
            Envelope envelope = Envelope.builder()
                    .version(version)
                    .algorithm(algorithm)
                    .keyId(keyId)
                    .keyVersion(keyVersion)
                    .nonce(nonce)
                    .salt(salt)
                    .aad(aad)
                    .ciphertext(ciphertext)
                    .tag(tag)
                    .createdAt(createdAt)
                    .format(format)
                    .binaryEncoding(encoding)
                    .attributes(attributes)
                    .headerHash(headerHash)
                    .build();
            validate(envelope);
            return envelope;
        } catch (IOException | IllegalArgumentException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, "Test envelope malformed");
        }
    }

    @Override
    public Envelope decodeText(String text) {
        try {
            return decode(Base64.getDecoder().decode(text));
        } catch (IllegalArgumentException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED, "Test text malformed");
        }
    }

    @Override
    public void validate(Envelope envelope) {
        if (!versionPolicy.isSupported(envelope.version())) {
            throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                    "Unsupported envelope version");
        }
        byte[] headerHash = envelope.headerHash();
        if (envelope.version() == 2 && headerHash.length != 32) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "v2 envelope requires a 32-byte header hash");
        }
        if (envelope.version() == 1 && headerHash.length != 0) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "v1 envelope must not carry a header hash");
        }
        if (!envelope.algorithm().isKnown()) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Unknown envelope algorithm");
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

    private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static byte[] readBytes(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > 16 * 1024 * 1024) {
            throw new IOException("Invalid test envelope length");
        }
        return input.readNBytes(length);
    }
}
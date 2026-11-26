package cn.tolim.spissatus4j.contract.envelope;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Canonical metadata binding for v2 envelopes.
 *
 * <p>The binding covers the metadata that is not already authenticated by the
 * AEAD/EtM tag: version, algorithm, key id, creation time, salt, KDF parameters
 * and user attributes. The key version is deliberately excluded because lazy
 * rotation may select it during encryption; selecting the wrong key version is
 * normally detected by the tag because the key material differs. If two key
 * versions share identical material, the tag cannot distinguish them; callers
 * that require a specific version should pin it. Nonces and ciphertext are
 * covered by the tag. Format and encoding are transport-level and are
 * validated structurally, not cryptographically. The effective AAD binding is
 * only meaningful for AEAD/EtM algorithms; asymmetric envelopes are not v2.</p>
 *
 * <p>The wire format is a library protocol; changing it requires a new domain
 * string and an envelope version.</p>
 */
public final class EnvelopeBinding {

    public static final int HEADER_HASH_BYTES = 32;

    private static final byte[] HEADER_DOMAIN =
            "cn.tolim.spissatus4j.envelope.header.v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD_DOMAIN =
            "cn.tolim.spissatus4j.envelope.aad.v1".getBytes(StandardCharsets.UTF_8);
    private static final int MAX_AAD_BYTES = 1_048_576;

    private EnvelopeBinding() {
    }

    public static byte[] headerHash(int version, AlgorithmId algorithm, KeyId keyId,
                                    Instant createdAt, Salt salt, KdfParameters kdf,
                                    Map<String, String> attributes) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(attributes, "attributes");
        ByteArrayOutputStream canonical = new ByteArrayOutputStream(256);
        writeBytes(canonical, HEADER_DOMAIN);
        writeInt(canonical, version);
        writeBytes(canonical, utf8(algorithm.id()));
        writeBytes(canonical, utf8(keyId.value()));
        writeLong(canonical, createdAt.toEpochMilli());
        writeBytes(canonical, salt == null ? new byte[0] : salt.asBytes());
        if (kdf == null) {
            canonical.write(0);
        } else {
            canonical.write(1);
            TreeMap<String, String> parameters = new TreeMap<>(kdf.toMap());
            writeInt(canonical, parameters.size());
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                writeBytes(canonical, utf8(entry.getKey()));
                writeBytes(canonical, utf8(entry.getValue()));
            }
        }
        TreeMap<String, String> sortedAttributes = new TreeMap<>(attributes);
        writeInt(canonical, sortedAttributes.size());
        for (Map.Entry<String, String> entry : sortedAttributes.entrySet()) {
            writeBytes(canonical, utf8(entry.getKey()));
            writeBytes(canonical, utf8(entry.getValue()));
        }
        return sha256(canonical.toByteArray());
    }

    public static byte[] headerHash(Envelope envelope) {
        Objects.requireNonNull(envelope, "envelope");
        return headerHash(envelope.version(), envelope.algorithm(), envelope.keyId(),
                envelope.createdAt(), envelope.salt(), envelope.kdfParameters(),
                envelope.attributes());
    }

    /**
     * Builds the effective AAD used by the cipher. The envelope stores the
     * user AAD only; a v2-aware decryptor reconstructs this value after
     * verifying the header hash.
     */
    public static AAD effectiveAad(AAD userAad, byte[] headerHash) {
        Objects.requireNonNull(userAad, "userAad");
        Objects.requireNonNull(headerHash, "headerHash");
        if (headerHash.length != HEADER_HASH_BYTES) {
            throw new IllegalArgumentException("headerHash must be 32 bytes");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(128 + userAad.length());
        writeBytes(output, AAD_DOMAIN);
        writeBytes(output, headerHash);
        writeBytes(output, userAad.asBytes());
        if (output.size() > MAX_AAD_BYTES) {
            throw new IllegalArgumentException("Effective AAD exceeds the maximum size");
        }
        return AAD.of(output.toByteArray());
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "SHA-256 is not available", e);
        }
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void writeBytes(ByteArrayOutputStream output, byte[] value) {
        writeInt(output, value.length);
        output.write(value, 0, value.length);
    }

    private static void writeInt(ByteArrayOutputStream output, int value) {
        output.write((value >>> 24) & 0xFF);
        output.write((value >>> 16) & 0xFF);
        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static void writeLong(ByteArrayOutputStream output, long value) {
        output.write((int) (value >>> 56) & 0xFF);
        output.write((int) (value >>> 48) & 0xFF);
        output.write((int) (value >>> 40) & 0xFF);
        output.write((int) (value >>> 32) & 0xFF);
        output.write((int) (value >>> 24) & 0xFF);
        output.write((int) (value >>> 16) & 0xFF);
        output.write((int) (value >>> 8) & 0xFF);
        output.write((int) value & 0xFF);
    }
}
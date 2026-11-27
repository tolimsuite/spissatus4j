package cn.tolim.spissatus4j.contract.envelope;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
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
 * ciphertext: version, algorithm, key id and key version, creation time, salt,
 * KDF parameters and user attributes. The key version is resolved before the
 * binding is computed, so lazy rotation stays inside one authorized operation
 * and a substituted version changes the authenticated metadata. Nonces and
 * ciphertext are covered by the AEAD/EtM tag. Format and encoding are
 * transport-level and are validated structurally, not cryptographically.</p>
 *
 * <p>AEAD/EtM envelopes authenticate the binding as domain-separated AAD.
 * Asymmetric ciphers accept no AAD, so their plaintext is prefixed with the
 * header hash inside the ciphertext; decryption strips it and rejects any
 * mismatch before returning plaintext.</p>
 *
 * <p>The wire format is a library protocol; changing it requires a new domain
 * string and an envelope version. The v2 domain below is the finalized
 * definition; the earlier v2 draft never shipped in a release.</p>
 */
public final class EnvelopeBinding {

    public static final int HEADER_HASH_BYTES = 32;

    /** Bytes prepended to asymmetric plaintext to carry the header binding. */
    public static final int ASYMMETRIC_BINDING_BYTES = HEADER_HASH_BYTES;

    private static final byte[] HEADER_DOMAIN =
            "cn.tolim.spissatus4j.envelope.header.v2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD_DOMAIN =
            "cn.tolim.spissatus4j.envelope.aad.v1".getBytes(StandardCharsets.UTF_8);
    private static final int MAX_AAD_BYTES = 1_048_576;
    private static final String GENERIC_FAILURE = "Envelope metadata authentication failed";

    private EnvelopeBinding() {
    }

    public static byte[] headerHash(int version, AlgorithmId algorithm, KeyId keyId,
                                    KeyVersion keyVersion, Instant createdAt, Salt salt,
                                    KdfParameters kdf, Map<String, String> attributes) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(keyVersion, "keyVersion");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(attributes, "attributes");
        ByteArrayOutputStream canonical = new ByteArrayOutputStream(256);
        writeBytes(canonical, HEADER_DOMAIN);
        writeInt(canonical, version);
        writeBytes(canonical, utf8(algorithm.id()));
        writeBytes(canonical, utf8(keyId.value()));
        writeLong(canonical, keyVersion.value());
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
                envelope.keyVersion(), envelope.createdAt(), envelope.salt(),
                envelope.kdfParameters(), envelope.attributes());
    }

    /**
     * Prefixes asymmetric plaintext with the header hash. The prefix lives
     * inside the ciphertext, so a decryptor can reject metadata tampering
     * before returning any plaintext even though asymmetric ciphers take no
     * associated data.
     */
    public static byte[] asymmetricPlaintext(byte[] plaintext, byte[] headerHash) {
        Objects.requireNonNull(plaintext, "plaintext");
        requireHeaderHash(headerHash);
        byte[] bound = new byte[ASYMMETRIC_BINDING_BYTES + plaintext.length];
        System.arraycopy(headerHash, 0, bound, 0, ASYMMETRIC_BINDING_BYTES);
        System.arraycopy(plaintext, 0, bound, ASYMMETRIC_BINDING_BYTES, plaintext.length);
        return bound;
    }

    /**
     * Verifies and removes the asymmetric plaintext prefix. Any mismatch or a
     * payload shorter than the prefix fails with the same generic binding
     * error, never with ciphertext detail.
     */
    public static byte[] verifyAsymmetricPlaintext(byte[] payload, byte[] headerHash) {
        Objects.requireNonNull(payload, "payload");
        requireHeaderHash(headerHash);
        if (payload.length < ASYMMETRIC_BINDING_BYTES) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_BINDING_MISMATCH, GENERIC_FAILURE);
        }
        byte[] prefix = new byte[ASYMMETRIC_BINDING_BYTES];
        System.arraycopy(payload, 0, prefix, 0, ASYMMETRIC_BINDING_BYTES);
        if (!MessageDigest.isEqual(prefix, headerHash)) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_BINDING_MISMATCH, GENERIC_FAILURE);
        }
        byte[] plaintext = new byte[payload.length - ASYMMETRIC_BINDING_BYTES];
        System.arraycopy(payload, ASYMMETRIC_BINDING_BYTES, plaintext, 0, plaintext.length);
        return plaintext;
    }

    private static void requireHeaderHash(byte[] headerHash) {
        Objects.requireNonNull(headerHash, "headerHash");
        if (headerHash.length != HEADER_HASH_BYTES) {
            throw new IllegalArgumentException("headerHash must be 32 bytes");
        }
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
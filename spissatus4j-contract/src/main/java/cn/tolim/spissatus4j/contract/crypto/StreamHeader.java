package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Metadata written at the beginning of a chunked AEAD stream. The header is
 * authenticated indirectly: every chunk derives its AAD from these values.
 *
 * @param version stream format version
 * @param algorithm AEAD algorithm
 * @param keyId key identifier
 * @param keyVersion key version
 * @param baseNonce base nonce; each chunk nonce preserves all base bytes and
 *                  XORs the big-endian chunk index into the last four bytes
 * @param chunkSize plaintext bytes per chunk
 * @param aad caller AAD bound into every chunk
 * @param createdAt creation time (informational, authenticated in header hash)
 * @param attributes non-sensitive stream attributes
 */
public record StreamHeader(
        int version,
        AlgorithmId algorithm,
        KeyId keyId,
        KeyVersion keyVersion,
        Nonce baseNonce,
        int chunkSize,
        AAD aad,
        Instant createdAt,
        Map<String, String> attributes) {

    public static final int CURRENT_VERSION = 1;

    public StreamHeader {
        if (version < 1) {
            throw new IllegalArgumentException("Stream version must be positive");
        }
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(keyVersion, "keyVersion");
        Objects.requireNonNull(baseNonce, "baseNonce");
        if (baseNonce.length() < 8) {
            throw new IllegalArgumentException("Stream base nonce must be at least 8 bytes");
        }
        if (chunkSize < 1024 || chunkSize > 16 * 1024 * 1024) {
            throw new IllegalArgumentException("chunkSize must be between 1 KiB and 16 MiB");
        }
        Objects.requireNonNull(aad, "aad");
        Objects.requireNonNull(createdAt, "createdAt");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    @Override
    public String toString() {
        return "StreamHeader[version=" + version + ", algorithm=" + algorithm + ", keyId=" + keyId
                + ", keyVersion=" + keyVersion + ", chunkSize=" + chunkSize + "]";
    }
}
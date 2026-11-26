package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.util.Map;
import java.util.Objects;

/** Request to open a chunked AEAD encrypting stream. */
public record StreamEncryptRequest(
        AlgorithmId algorithm,
        KeyId keyId,
        Long keyVersion,
        int chunkSize,
        AAD aad,
        CallerContext caller,
        Map<String, String> attributes) {

    public static final int DEFAULT_CHUNK_SIZE = 64 * 1024;

    public StreamEncryptRequest {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        if (chunkSize < 1024 || chunkSize > 16 * 1024 * 1024) {
            throw new IllegalArgumentException("chunkSize must be between 1 KiB and 16 MiB");
        }
        aad = aad == null ? AAD.empty() : aad;
        Objects.requireNonNull(caller, "caller");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
    }

    public static StreamEncryptRequest of(AlgorithmId algorithm, KeyId keyId, CallerContext caller) {
        return new StreamEncryptRequest(algorithm, keyId, null, DEFAULT_CHUNK_SIZE, AAD.empty(), caller, Map.of());
    }
}
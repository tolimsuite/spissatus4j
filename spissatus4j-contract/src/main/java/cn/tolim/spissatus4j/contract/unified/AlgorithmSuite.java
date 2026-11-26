package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyType;
import java.util.Objects;
import java.util.Set;

/**
 * Named preset that pins exactly one encryption algorithm plus minimum key
 * size and allowed key types. It does not introduce a new algorithm.
 */
public record AlgorithmSuite(
        String id,
        AlgorithmId algorithm,
        int minKeyBits,
        Set<KeyType> keyTypes) {

    public static final AlgorithmSuite AEAD_AES_256_GCM = new AlgorithmSuite(
            "AEAD-AES-256-GCM", AlgorithmId.AES_GCM, 256,
            Set.of(KeyType.AES, KeyType.SYMMETRIC, KeyType.RAW));

    public static final AlgorithmSuite AEAD_CHACHA20_POLY1305 = new AlgorithmSuite(
            "AEAD-CHACHA20-POLY1305", AlgorithmId.CHACHA20_POLY1305, 256,
            Set.of(KeyType.SYMMETRIC, KeyType.RAW));

    public static final AlgorithmSuite AEAD_SM4_GCM = new AlgorithmSuite(
            "AEAD-SM4-GCM", AlgorithmId.SM4_GCM, 128,
            Set.of(KeyType.SM4, KeyType.SYMMETRIC, KeyType.RAW));

    public AlgorithmSuite {
        id = Objects.requireNonNull(id, "id").trim();
        if (id.isEmpty()) {
            throw new IllegalArgumentException("Suite id must not be blank");
        }
        Objects.requireNonNull(algorithm, "algorithm");
        if (minKeyBits < 0) {
            throw new IllegalArgumentException("minKeyBits must not be negative");
        }
        keyTypes = Set.copyOf(Objects.requireNonNull(keyTypes, "keyTypes"));
        if (keyTypes.isEmpty()) {
            throw new IllegalArgumentException("Suite must allow at least one key type");
        }
    }

    /** Resolves a documented preset; unknown identifiers are rejected. */
    public static AlgorithmSuite of(String id) {
        Objects.requireNonNull(id, "id");
        return switch (id.trim()) {
            case "AEAD-AES-256-GCM" -> AEAD_AES_256_GCM;
            case "AEAD-CHACHA20-POLY1305" -> AEAD_CHACHA20_POLY1305;
            case "AEAD-SM4-GCM" -> AEAD_SM4_GCM;
            default -> throw new IllegalArgumentException("Unknown algorithm suite");
        };
    }
}
package cn.tolim.spissatus4j.contract.algorithm;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable metadata about an algorithm: family, security posture, minimum
 * key size, nonce/tag sizes and the key usages it may serve.
 *
 * @param id stable identifier
 * @param displayName human-readable name
 * @param family coarse family
 * @param status security posture (unknown for unregistered algorithms)
 * @param minKeyBits minimum acceptable key size in bits (0 when not applicable)
 * @param nonceBytes expected nonce/IV size in bytes (0 when not applicable)
 * @param tagBytes expected authentication tag size in bytes (0 when none)
 * @param usages allowed key usages; empty for keyless primitives
 * @param fipsApproved whether an approved implementation may be used in FIPS mode
 * @param gm whether the algorithm belongs to the Chinese GM/T suite
 * @param postQuantum whether the algorithm is designed to resist quantum attacks
 * @param notes short non-sensitive remark
 */
public record AlgorithmInfo(
        AlgorithmId id,
        String displayName,
        AlgorithmFamily family,
        SecurityStatus status,
        int minKeyBits,
        int nonceBytes,
        int tagBytes,
        Set<KeyUsage> usages,
        boolean fipsApproved,
        boolean gm,
        boolean postQuantum,
        String notes) {

    public AlgorithmInfo {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(family, "family");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(notes, "notes");
        usages = Set.copyOf(Objects.requireNonNull(usages, "usages"));
        if (minKeyBits < 0 || nonceBytes < 0 || tagBytes < 0) {
            throw new IllegalArgumentException("Sizes must not be negative");
        }
    }

    public static AlgorithmInfo unknown(String id) {
        AlgorithmId algorithmId = AlgorithmId.of(id);
        return new AlgorithmInfo(algorithmId, id, AlgorithmFamily.UNKNOWN, SecurityStatus.UNKNOWN,
                0, 0, 0, Set.of(), false, false, false, "Unregistered algorithm");
    }

    public boolean supportsUsage(KeyUsage usage) {
        return usages.contains(usage);
    }

    public boolean deprecated() {
        return status == SecurityStatus.DEPRECATED;
    }

    public boolean prohibited() {
        return status == SecurityStatus.PROHIBITED || status == SecurityStatus.UNKNOWN;
    }
}
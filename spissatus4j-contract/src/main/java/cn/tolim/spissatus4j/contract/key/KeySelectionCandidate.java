package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * Minimal, non-secret key metadata returned by advisory selection
 * enumeration.
 *
 * <p>Unlike {@link KeyDescriptor}, it carries no attributes, fingerprint,
 * rotation policy or usage counters, so automatic selection does not bypass
 * the read policy for richer key metadata. The authoritative policy decision
 * later receives the full descriptor of the selected key.</p>
 */
public record KeySelectionCandidate(
        KeyId keyId,
        KeyVersion version,
        KeyType type,
        AlgorithmId algorithm,
        int keyBits,
        KeyState state,
        Set<KeyUsage> usages,
        String tenantId,
        Instant expiresAt) {

    public KeySelectionCandidate {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(state, "state");
        usages = Set.copyOf(Objects.requireNonNull(usages, "usages"));
        Objects.requireNonNull(tenantId, "tenantId");
        if (keyBits < 0) {
            throw new IllegalArgumentException("keyBits must not be negative");
        }
    }

    public static KeySelectionCandidate from(KeyDescriptor descriptor) {
        Objects.requireNonNull(descriptor, "descriptor");
        return new KeySelectionCandidate(descriptor.keyId(), descriptor.version(),
                descriptor.type(), descriptor.algorithm(), descriptor.keyBits(),
                descriptor.state(), descriptor.usages(), descriptor.tenantId(),
                descriptor.expiresAt());
    }

    public boolean supportsUsage(KeyUsage usage) {
        return usages.contains(usage);
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }
}
package cn.tolim.spissatus4j.contract.key;

import java.time.Duration;
import java.util.Objects;

/**
 * Rotation trigger and retention settings for a logical key.
 *
 * @param maxAge maximum age before lazy rotation (null disables age trigger)
 * @param maxOperations maximum protecting operations before lazy rotation (0 disables)
 * @param retainVersions number of historical versions kept for decryption
 */
public record RotationPolicy(Duration maxAge, long maxOperations, int retainVersions) {

    public RotationPolicy {
        if (maxAge != null && (maxAge.isNegative() || maxAge.isZero())) {
            throw new IllegalArgumentException("maxAge must be positive");
        }
        if (maxOperations < 0) {
            throw new IllegalArgumentException("maxOperations must not be negative");
        }
        if (retainVersions < 1 || retainVersions > 1000) {
            throw new IllegalArgumentException("retainVersions must be between 1 and 1000");
        }
    }

    public static RotationPolicy defaults() {
        return new RotationPolicy(Duration.ofDays(90), 1_000_000, 3);
    }

    public static RotationPolicy disabled() {
        return new RotationPolicy(null, 0, 3);
    }

    public RotationPolicy withRetainVersions(int versions) {
        return new RotationPolicy(maxAge, maxOperations, versions);
    }

    public boolean ageTriggered(java.time.Instant createdAt, java.time.Instant now) {
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(now, "now");
        return maxAge != null && createdAt.plus(maxAge).isBefore(now);
    }

    public boolean operationsTriggered(long usageCount) {
        return maxOperations > 0 && usageCount >= maxOperations;
    }
}
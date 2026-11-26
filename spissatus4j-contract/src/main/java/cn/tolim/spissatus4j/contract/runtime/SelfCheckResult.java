package cn.tolim.spissatus4j.contract.runtime;

import java.time.Duration;
import java.util.Objects;

/**
 * Result of one startup known-answer or health check.
 *
 * @param checkId stable check identifier
 * @param status UP, DEGRADED or DOWN
 * @param message non-sensitive diagnostic
 * @param duration elapsed time
 */
public record SelfCheckResult(String checkId, HealthStatus status, String message, Duration duration) {

    public SelfCheckResult {
        Objects.requireNonNull(checkId, "checkId");
        Objects.requireNonNull(status, "status");
        message = Objects.requireNonNull(message, "message");
        Objects.requireNonNull(duration, "duration");
    }

    public static SelfCheckResult up(String checkId, String message) {
        return new SelfCheckResult(checkId, HealthStatus.UP, message, Duration.ZERO);
    }

    public static SelfCheckResult down(String checkId, String message) {
        return new SelfCheckResult(checkId, HealthStatus.DOWN, message, Duration.ZERO);
    }

    public static SelfCheckResult degraded(String checkId, String message) {
        return new SelfCheckResult(checkId, HealthStatus.DEGRADED, message, Duration.ZERO);
    }
}
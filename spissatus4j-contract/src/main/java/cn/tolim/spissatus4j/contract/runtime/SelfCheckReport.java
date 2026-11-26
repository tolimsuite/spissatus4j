package cn.tolim.spissatus4j.contract.runtime;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Aggregated startup self-check report. Any DOWN check makes the overall
 * result DOWN; otherwise any DEGRADED makes it DEGRADED.
 */
public record SelfCheckReport(Instant startedAt, Instant completedAt, List<SelfCheckResult> checks) {

    public SelfCheckReport {
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(completedAt, "completedAt");
        checks = List.copyOf(Objects.requireNonNull(checks, "checks"));
    }

    public static SelfCheckReport of(List<SelfCheckResult> checks) {
        Instant now = Instant.now();
        return new SelfCheckReport(now, now, checks);
    }

    public HealthStatus overall() {
        boolean degraded = false;
        for (SelfCheckResult check : checks) {
            if (check.status() == HealthStatus.DOWN) {
                return HealthStatus.DOWN;
            }
            degraded |= check.status() == HealthStatus.DEGRADED;
        }
        return degraded ? HealthStatus.DEGRADED : HealthStatus.UP;
    }

    public boolean passed() {
        return overall() == HealthStatus.UP;
    }

    public Duration duration() {
        return Duration.between(startedAt, completedAt);
    }

    public List<SelfCheckResult> failures() {
        return checks.stream().filter(c -> c.status() == HealthStatus.DOWN).toList();
    }

    public SelfCheckReport withPrefix(String prefix) {
        List<SelfCheckResult> prefixed = checks.stream()
                .map(c -> new SelfCheckResult(prefix + "." + c.checkId(), c.status(), c.message(), c.duration()))
                .toList();
        return new SelfCheckReport(startedAt, completedAt, prefixed);
    }
}
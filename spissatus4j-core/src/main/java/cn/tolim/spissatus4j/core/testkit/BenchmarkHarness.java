package cn.tolim.spissatus4j.core.testkit;

import java.time.Duration;
import java.util.Objects;

/**
 * Lightweight benchmark helper (no JMH dependency). Not intended for
 * publication microbenchmarks; use it to catch pathological regressions.
 */
public final class BenchmarkHarness {

    private BenchmarkHarness() {
    }

    public record Result(Duration total, int iterations, double averageNanos) {
    }

    public static Result measure(Runnable task, int warmupIterations, int measuredIterations) {
        Objects.requireNonNull(task, "task");
        if (warmupIterations < 0 || measuredIterations < 1) {
            throw new IllegalArgumentException("Invalid iteration counts");
        }
        for (int i = 0; i < warmupIterations; i++) {
            task.run();
        }
        long started = System.nanoTime();
        for (int i = 0; i < measuredIterations; i++) {
            task.run();
        }
        long elapsed = System.nanoTime() - started;
        return new Result(Duration.ofNanos(elapsed), measuredIterations,
                (double) elapsed / measuredIterations);
    }
}
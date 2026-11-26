package cn.tolim.spissatus4j.core.testkit;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.IntConsumer;

/** Virtual-thread concurrency harness for deterministic stress tests. */
public final class ConcurrencyHarness {

    private ConcurrencyHarness() {
    }

    public static void run(int threads, int iterationsPerThread, IntConsumer task) {
        if (threads < 1 || iterationsPerThread < 1) {
            throw new IllegalArgumentException("threads and iterations must be positive");
        }
        Objects.requireNonNull(task, "task");
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (int thread = 0; thread < threads; thread++) {
                int threadIndex = thread;
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    for (int iteration = 0; iteration < iterationsPerThread; iteration++) {
                        task.accept(threadIndex);
                    }
                    return null;
                }));
            }
            ready.await();
            start.countDown();
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (ExecutionException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException runtime) {
                        throw runtime;
                    }
                    if (cause instanceof Error error) {
                        throw error;
                    }
                    throw new AssertionError(cause);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Concurrency harness interrupted", e);
        }
    }

    public static void runAll(int threads, Runnable task) {
        run(threads, 1, ignored -> task.run());
    }

    /** Utility to wait for a latch in tests without failing on timeout. */
    public static void await(CountDownLatch latch, long timeoutSeconds) {
        try {
            if (!latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
                throw new AssertionError("Latch timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted", e);
        }
    }
}
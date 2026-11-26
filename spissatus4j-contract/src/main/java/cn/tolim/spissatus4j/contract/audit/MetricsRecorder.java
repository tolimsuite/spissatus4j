package cn.tolim.spissatus4j.contract.audit;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.Map;

/**
 * Minimal metrics abstraction. Tag values must never contain key material,
 * plaintext, passwords or high-cardinality user data.
 */
public interface MetricsRecorder {

    void increment(String name, Map<String, String> tags, long delta);

    default void increment(String name, Map<String, String> tags) {
        increment(name, tags, 1);
    }

    void observe(String name, double value, Map<String, String> tags);

    void gauge(String name, double value, Map<String, String> tags);

    /**
     * Read-only snapshot used by management endpoints. The default is empty so
     * write-only recorders remain compatible; implementations should expose
     * bounded, non-sensitive aggregates only.
     */
    default Map<String, Double> snapshot() {
        return Map.of();
    }

    HealthStatus health();
}
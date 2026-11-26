package cn.tolim.spissatus4j.core.audit;

import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.LongAdder;

/**
 * Dependency-free metrics recorder. Invalid metric names or tags are dropped
 * rather than thrown, so instrumentation can never break a cryptographic
 * operation. Snapshot keys use a stable {@code name{k=v}} form.
 */
public final class DefaultMetricsRecorder implements MetricsRecorder {

    private final ConcurrentHashMap<String, LongAdder> counters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, DoubleAdder> observations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LongAdder> observationCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Double> gauges = new ConcurrentHashMap<>();

    @Override
    public void increment(String name, Map<String, String> tags, long delta) {
        String key = key(name, tags);
        if (key != null) {
            counters.computeIfAbsent(key, ignored -> new LongAdder()).add(delta);
        }
    }

    @Override
    public void observe(String name, double value, Map<String, String> tags) {
        String key = key(name, tags);
        if (key != null) {
            observations.computeIfAbsent(key, ignored -> new DoubleAdder()).add(value);
            observationCounts.computeIfAbsent(key, ignored -> new LongAdder()).increment();
        }
    }

    @Override
    public void gauge(String name, double value, Map<String, String> tags) {
        String key = key(name, tags);
        if (key != null) {
            gauges.put(key, value);
        }
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }

    public Map<String, Double> snapshot() {
        Map<String, Double> result = new LinkedHashMap<>();
        counters.forEach((key, value) -> result.put(key, value.doubleValue()));
        gauges.forEach(result::put);
        observations.forEach((key, value) -> {
            result.put(key + ".sum", value.doubleValue());
            LongAdder count = observationCounts.get(key);
            result.put(key + ".count", count == null ? 0d : count.doubleValue());
        });
        return Map.copyOf(result);
    }

    private static String key(String name, Map<String, String> tags) {
        if (name == null || name.isBlank() || name.length() > 128) {
            return null;
        }
        StringBuilder sb = new StringBuilder(name);
        if (tags != null && !tags.isEmpty()) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, String> entry : tags.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey()).toList()) {
                if (entry.getKey() == null || entry.getValue() == null
                        || entry.getKey().length() > 128 || entry.getValue().length() > 256
                        || entry.getKey().indexOf('\n') >= 0 || entry.getValue().indexOf('\n') >= 0) {
                    return null;
                }
                if (!first) {
                    sb.append(',');
                }
                sb.append(entry.getKey()).append('=').append(entry.getValue());
                first = false;
            }
            sb.append('}');
        }
        return sb.toString();
    }
}
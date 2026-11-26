package cn.tolim.spissatus4j.core.audit;

import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/** Bounded in-memory audit sink used by the default trail and tests. */
public final class InMemoryAuditSink implements AuditSink {

    private final Deque<AuditEvent> events = new ArrayDeque<>();
    private final int maxEntries;

    public InMemoryAuditSink(int maxEntries) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.maxEntries = maxEntries;
    }

    @Override
    public String sinkId() {
        return "memory";
    }

    @Override
    public synchronized void write(AuditEvent event) {
        events.addLast(event);
        while (events.size() > maxEntries) {
            events.removeFirst();
        }
    }

    public synchronized List<AuditEvent> snapshot() {
        return List.copyOf(new ArrayList<>(events));
    }

    public synchronized int size() {
        return events.size();
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }
}
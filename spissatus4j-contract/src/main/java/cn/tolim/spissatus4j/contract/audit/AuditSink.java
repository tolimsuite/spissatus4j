package cn.tolim.spissatus4j.contract.audit;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;

/**
 * Destination for audit events (file, database, message queue, SIEM).
 *
 * <p>A sink failure must never be silently discarded: the trail reports it
 * through health, metrics and an alert, and optionally fails the operation.</p>
 */
public interface AuditSink {

    String sinkId();

    void write(AuditEvent event);

    default void flush() {
    }

    HealthStatus health();

    default void close() {
    }
}
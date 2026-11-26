package cn.tolim.spissatus4j.contract.audit;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;

/** Receives operational alerts. Channel failures are recorded, never silent. */
public interface AlertSink {

    String sinkId();

    void raise(Alert alert);

    HealthStatus health();

    default void close() {
    }
}
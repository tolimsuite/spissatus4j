package cn.tolim.spissatus4j.contract.runtime;

/** Lifecycle state of the facade runtime. */
public enum RuntimeState {
    STARTING,
    READY,
    DEGRADED,
    UNAVAILABLE,
    CLOSED;

    public boolean isOperational() {
        return this == READY || this == DEGRADED;
    }
}
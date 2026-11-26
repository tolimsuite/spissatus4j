package cn.tolim.spissatus4j.contract.runtime;

/**
 * Fail-closed gate executed before every sensitive operation. When the runtime
 * is unavailable or closed, operations are rejected rather than downgraded.
 */
public interface FailClosedGuard {

    RuntimeState state();

    default boolean isOperational() {
        return state().isOperational();
    }

    void ensureOperational(String operation);

    void markUnavailable(String reason);
}
package cn.tolim.spissatus4j.core.runtime;

import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.RuntimeSecurityException;
import cn.tolim.spissatus4j.contract.runtime.FailClosedGuard;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Fail-closed guard. Operations are permitted only in READY and DEGRADED
 * states; UNAVAILABLE and CLOSED reject every sensitive operation.
 */
public final class DefaultFailClosedGuard implements FailClosedGuard {

    private static final System.Logger LOG = System.getLogger(DefaultFailClosedGuard.class.getName());

    private final AtomicReference<RuntimeState> state =
            new AtomicReference<>(RuntimeState.STARTING);

    public DefaultFailClosedGuard(RuntimeState initialState) {
        state.set(Objects.requireNonNull(initialState, "initialState"));
    }

    @Override
    public RuntimeState state() {
        return state.get();
    }

    @Override
    public void ensureOperational(String operation) {
        RuntimeState current = state.get();
        if (!current.isOperational()) {
            throw new RuntimeSecurityException(ErrorCode.RUNTIME_UNAVAILABLE,
                    "Runtime is not operational (" + current + ")");
        }
    }

    @Override
    public void markUnavailable(String reason) {
        state.set(RuntimeState.UNAVAILABLE);
        LOG.log(System.Logger.Level.ERROR, "spissatus4j runtime marked unavailable: {0}",
                reason == null ? "unspecified" : reason);
    }

    public void transitionTo(RuntimeState newState) {
        state.set(Objects.requireNonNull(newState, "newState"));
    }

    public void close() {
        state.set(RuntimeState.CLOSED);
    }
}
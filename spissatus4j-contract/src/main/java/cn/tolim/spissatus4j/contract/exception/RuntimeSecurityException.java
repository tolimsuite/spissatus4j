package cn.tolim.spissatus4j.contract.exception;

/**
 * A runtime security invariant was violated: nonce reuse, failed self-check,
 * unavailable fail-closed guard, stream ordering violation, and similar.
 */
public final class RuntimeSecurityException extends SpissatusException {

    public RuntimeSecurityException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public RuntimeSecurityException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
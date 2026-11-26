package cn.tolim.spissatus4j.contract.exception;

/** Audit sink failure, broken audit chain, or audit serialization failure. */
public final class AuditException extends SpissatusException {

    public AuditException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public AuditException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
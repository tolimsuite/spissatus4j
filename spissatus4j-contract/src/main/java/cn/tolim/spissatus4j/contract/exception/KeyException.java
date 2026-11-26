package cn.tolim.spissatus4j.contract.exception;

/** Key lifecycle, usage, versioning, storage or wrapping failure. */
public final class KeyException extends SpissatusException {

    public KeyException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public KeyException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
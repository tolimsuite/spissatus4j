package cn.tolim.spissatus4j.contract.exception;

/** A security policy denied the operation, or policy evaluation was unavailable. */
public final class PolicyException extends SpissatusException {

    public PolicyException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public PolicyException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
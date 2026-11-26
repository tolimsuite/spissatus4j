package cn.tolim.spissatus4j.contract.exception;

/** Malformed, unsupported or invalid self-describing envelope. */
public final class EnvelopeException extends SpissatusException {

    public EnvelopeException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public EnvelopeException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
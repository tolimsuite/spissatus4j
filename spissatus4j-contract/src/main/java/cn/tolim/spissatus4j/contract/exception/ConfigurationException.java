package cn.tolim.spissatus4j.contract.exception;

/** Invalid configuration, missing dependency, or failed startup self-check. */
public final class ConfigurationException extends SpissatusException {

    public ConfigurationException(String message) {
        super(ErrorCode.CONFIGURATION_INVALID, message);
    }

    public ConfigurationException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public ConfigurationException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
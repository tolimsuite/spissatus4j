package cn.tolim.spissatus4j.contract.exception;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.util.Objects;

/**
 * Cryptographic operation failure. Detail is deliberately suppressed for
 * authentication failures so callers cannot distinguish padding, tag and key
 * errors.
 */
public final class CryptoException extends SpissatusException {

    public CryptoException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public CryptoException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    /** A generic authentication failure with no oracle-friendly detail. */
    public static CryptoException authenticationFailed(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        return new CryptoException(ErrorCode.AUTHENTICATION_FAILED,
                "Cryptographic authentication failed");
    }

    public static CryptoException unsupported(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        return new CryptoException(ErrorCode.ALGORITHM_UNSUPPORTED,
                "Algorithm is not supported by any installed provider: " + algorithm.id());
    }
}
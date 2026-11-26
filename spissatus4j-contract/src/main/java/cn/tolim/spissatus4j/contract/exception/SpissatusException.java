package cn.tolim.spissatus4j.contract.exception;

import java.util.Objects;

/**
 * Sealed root of the library exception hierarchy.
 *
 * <p>Exactly seven families are defined: configuration, key, cryptography,
 * policy, envelope, audit and runtime security. Keeping the hierarchy sealed
 * prevents implementations from inventing incompatible failure models.</p>
 *
 * <p>No subclass message may contain secrets. Authentication failures in
 * particular must use a generic message so that decryption oracles cannot be
 * built from error text.</p>
 */
public abstract sealed class SpissatusException extends RuntimeException
        permits ConfigurationException, KeyException, CryptoException, PolicyException,
        EnvelopeException, AuditException, RuntimeSecurityException {

    private final ErrorCode errorCode;

    protected SpissatusException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
    }

    protected SpissatusException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
    }

    public final ErrorCode errorCode() {
        return errorCode;
    }

    /** Audit-safe textual form; never includes a cause's class name on its own. */
    public final String toSafeString() {
        return getClass().getSimpleName() + "[" + errorCode + "]: " + getMessage();
    }
}
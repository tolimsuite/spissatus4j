package cn.tolim.spissatus4j.contract.exception;

/**
 * Stable machine-readable error codes shared by every module.
 *
 * <p>Codes are part of the public contract: they are used by policy rules,
 * audit records, metrics dashboards and callers. Never reuse or renumber a
 * code. Messages are intentionally coarse and must never contain key
 * material, plaintext, passwords or complete ciphertext.</p>
 */
public enum ErrorCode {
    // configuration / lifecycle
    CONFIGURATION_INVALID,
    MISSING_DEPENDENCY,
    SELF_CHECK_FAILED,
    RUNTIME_UNAVAILABLE,
    INTERNAL_ERROR,

    // algorithms
    ALGORITHM_UNKNOWN,
    ALGORITHM_UNSUPPORTED,
    ALGORITHM_PROHIBITED,
    ALGORITHM_DEPRECATED,
    ALGORITHM_EXPERIMENTAL,
    MIN_KEY_BITS_VIOLATION,
    COMPLIANCE_VIOLATION,
    INVALID_PARAMETER,
    UNSUPPORTED_OPERATION,

    // keys
    KEY_NOT_FOUND,
    KEY_NOT_ACTIVE,
    KEY_DESTROYED,
    KEY_USAGE_VIOLATION,
    KEY_VERSION_NOT_FOUND,
    ILLEGAL_KEY_TRANSITION,
    KEY_EXPORT_DENIED,
    KEY_WRAP_FAILED,
    KEY_PROVIDER_FAILURE,
    KEY_ALREADY_EXISTS,
    KEY_IMPORT_FAILED,

    // cryptography
    AUTHENTICATION_FAILED,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    SIGNATURE_VERIFICATION_FAILED,
    INVALID_CIPHERTEXT,
    NONCE_REUSE,
    NONCE_INVALID,
    TAG_INVALID,
    PROVIDER_FAILURE,

    // envelope
    ENVELOPE_MALFORMED,
    ENVELOPE_VALIDATION_FAILED,
    UNSUPPORTED_ENVELOPE_VERSION,
    ENVELOPE_CODEC_FAILURE,

    // policy
    POLICY_DENIED,
    POLICY_UNAVAILABLE,
    ACCESS_DENIED,
    TENANT_VIOLATION,
    RATE_LIMITED,
    QUOTA_EXCEEDED,
    COMPLIANCE_MODE_DENIED,

    // audit
    AUDIT_FAILURE,
    AUDIT_CHAIN_BROKEN,

    // streaming
    STREAM_CORRUPTED,
    STREAM_TRUNCATED,
    STREAM_ORDER_VIOLATION,
    STREAM_LIMIT_EXCEEDED,

    // unified entry point (append-only; never reuse or renumber)
    ALGORITHM_SELECTION_FAILED,
    ALGORITHM_SELECTION_AMBIGUOUS,
    KEY_ALGORITHM_MISMATCH,
    ENVELOPE_BINDING_MISMATCH,
    LEGACY_ENVELOPE_DENIED
}
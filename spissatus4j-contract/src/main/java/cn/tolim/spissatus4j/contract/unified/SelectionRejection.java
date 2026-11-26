package cn.tolim.spissatus4j.contract.unified;

/**
 * Stable, non-sensitive reason why a candidate algorithm/key pair was rejected
 * during unified selection. These values are safe for diagnostics and metrics.
 */
public enum SelectionRejection {
    SELECTED,
    NOT_IN_PROFILE,
    ALGORITHM_UNKNOWN,
    ALGORITHM_PROHIBITED,
    ALGORITHM_DEPRECATED,
    ALGORITHM_EXPERIMENTAL,
    COMPLIANCE_MODE,
    PROVIDER_UNAVAILABLE,
    KEY_NOT_FOUND,
    KEY_NOT_ACTIVE,
    KEY_USAGE,
    KEY_TENANT,
    KEY_EXPIRED,
    KEY_SIZE,
    KEY_ALGORITHM_MISMATCH,
    KEY_TYPE_MISMATCH,
    POLICY_HINT_DENIED,
    AAD_UNSUPPORTED
}
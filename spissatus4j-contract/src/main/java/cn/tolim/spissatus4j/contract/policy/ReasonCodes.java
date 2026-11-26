package cn.tolim.spissatus4j.contract.policy;

/** Stable reason codes used by policy decisions, metrics and audits. */
public final class ReasonCodes {

    public static final String ALLOWED = "ALLOWED";
    public static final String ALGORITHM_UNKNOWN = "ALGORITHM_UNKNOWN";
    public static final String ALGORITHM_PROHIBITED = "ALGORITHM_PROHIBITED";
    public static final String ALGORITHM_DEPRECATED = "ALGORITHM_DEPRECATED";
    public static final String ALGORITHM_EXPERIMENTAL = "ALGORITHM_EXPERIMENTAL";
    public static final String ALGORITHM_NOT_ALLOWED = "ALGORITHM_NOT_ALLOWED";
    public static final String MIN_KEY_BITS = "MIN_KEY_BITS";
    public static final String KEY_USAGE_MISMATCH = "KEY_USAGE_MISMATCH";
    public static final String KEY_NOT_ACTIVE = "KEY_NOT_ACTIVE";
    public static final String KEY_EXPIRED = "KEY_EXPIRED";
    public static final String ANONYMOUS_CALLER = "ANONYMOUS_CALLER";
    public static final String CALLER_NOT_AUTHORIZED = "CALLER_NOT_AUTHORIZED";
    public static final String ACCESS_DENIED = "ACCESS_DENIED";
    public static final String TENANT_MISMATCH = "TENANT_MISMATCH";
    public static final String CROSS_TENANT_DENIED = "CROSS_TENANT_DENIED";
    public static final String RATE_LIMITED = "RATE_LIMITED";
    public static final String QUOTA_EXCEEDED = "QUOTA_EXCEEDED";
    public static final String POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE";
    public static final String POLICY_SOURCE_UNAVAILABLE = "POLICY_SOURCE_UNAVAILABLE";
    public static final String COMPLIANCE_MODE_VIOLATION = "COMPLIANCE_MODE_VIOLATION";
    public static final String FIPS_MODE_VIOLATION = "FIPS_MODE_VIOLATION";
    public static final String GM_MODE_VIOLATION = "GM_MODE_VIOLATION";
    public static final String NONCE_REUSE = "NONCE_REUSE";
    public static final String AUDIT_FAILURE = "AUDIT_FAILURE";
    public static final String SELF_CHECK_FAILED = "SELF_CHECK_FAILED";

    private ReasonCodes() {
    }
}
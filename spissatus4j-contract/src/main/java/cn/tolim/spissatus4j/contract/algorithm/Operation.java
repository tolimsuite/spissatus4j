package cn.tolim.spissatus4j.contract.algorithm;

/** Operation type used in policy requests and audit records. */
public enum Operation {
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    DIGEST,
    MAC,
    VERIFY_MAC,
    DERIVE_KEY,
    WRAP,
    UNWRAP,
    GENERATE_KEY,
    IMPORT_KEY,
    ROTATE_KEY,
    ACTIVATE_KEY,
    DEACTIVATE_KEY,
    REVOKE_KEY,
    COMPROMISE_KEY,
    DESTROY_KEY,
    EXPORT_PUBLIC_KEY,
    READ_KEY,
    STREAM_ENCRYPT,
    STREAM_DECRYPT,
    POLICY_ADMIN
}
package cn.tolim.spissatus4j.contract.algorithm;

/** Purpose a managed key may serve. Usage isolation is mandatory. */
public enum KeyUsage {
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    WRAP,
    UNWRAP,
    MAC,
    DERIVE
}
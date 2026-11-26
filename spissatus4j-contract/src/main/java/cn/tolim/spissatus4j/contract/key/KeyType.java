package cn.tolim.spissatus4j.contract.key;

/** Material kind of a managed key. */
public enum KeyType {
    SYMMETRIC,
    AES,
    SM4,
    HMAC,
    RSA,
    EC,
    ED25519,
    ED448,
    SM2,
    KEM,
    RAW
}
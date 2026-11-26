package cn.tolim.spissatus4j.contract.key;

/** Supported key import encodings. Private key export is never supported. */
public enum ImportFormat {
    RAW,
    PKCS8,
    X509,
    PEM,
    JWK
}
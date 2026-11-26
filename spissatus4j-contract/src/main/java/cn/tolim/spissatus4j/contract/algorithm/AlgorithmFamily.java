package cn.tolim.spissatus4j.contract.algorithm;

/** Coarse algorithm classification used for routing, policy and compliance. */
public enum AlgorithmFamily {
    SYMMETRIC,
    AEAD,
    ASYMMETRIC,
    KEM,
    HASH,
    MAC,
    SIGNATURE,
    KDF,
    RANDOM,
    UNKNOWN
}
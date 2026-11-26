package cn.tolim.spissatus4j.contract.envelope;

/**
 * Transport encoding applied to serialized envelope bytes. Encoding is not
 * encryption and must never be used as a confidentiality mechanism.
 */
public enum BinaryEncoding {
    RAW,
    BASE64,
    BASE64URL,
    HEX
}
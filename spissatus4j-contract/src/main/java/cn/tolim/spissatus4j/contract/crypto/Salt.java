package cn.tolim.spissatus4j.contract.crypto;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/** Immutable KDF salt. Bytes are copied on construction and access. */
public final class Salt {

    private static final Salt EMPTY = new Salt(new byte[0]);

    private final byte[] value;

    private Salt(byte[] value) {
        this.value = value;
    }

    public static Salt of(byte[] value) {
        Objects.requireNonNull(value, "value");
        if (value.length > 256) {
            throw new IllegalArgumentException("Salt must not exceed 256 bytes");
        }
        return value.length == 0 ? EMPTY : new Salt(value.clone());
    }

    public static Salt empty() {
        return EMPTY;
    }

    public byte[] asBytes() {
        return value.clone();
    }

    public int length() {
        return value.length;
    }

    public boolean isEmpty() {
        return value.length == 0;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Salt salt && MessageDigest.isEqual(value, salt.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "Salt[length=" + value.length + "]";
    }
}
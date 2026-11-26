package cn.tolim.spissatus4j.contract.crypto;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable Nonce/IV value. Bytes are copied on construction and on access.
 * {@link #toString()} never reveals the value.
 */
public final class Nonce {

    private static final Nonce EMPTY = new Nonce(new byte[0]);

    private final byte[] value;

    private Nonce(byte[] value) {
        this.value = value;
    }

    public static Nonce of(byte[] value) {
        Objects.requireNonNull(value, "value");
        if (value.length > 64) {
            throw new IllegalArgumentException("Nonce must not exceed 64 bytes");
        }
        return value.length == 0 ? EMPTY : new Nonce(value.clone());
    }

    public static Nonce empty() {
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
        return other instanceof Nonce nonce && MessageDigest.isEqual(value, nonce.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "Nonce[length=" + value.length + "]";
    }
}
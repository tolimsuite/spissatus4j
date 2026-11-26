package cn.tolim.spissatus4j.contract.crypto;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable additional authenticated data. AAD participates in AEAD tag
 * verification and is never treated as secret.
 */
public final class AAD {

    private static final AAD EMPTY = new AAD(new byte[0]);

    private final byte[] value;

    private AAD(byte[] value) {
        this.value = value;
    }

    public static AAD of(byte[] value) {
        Objects.requireNonNull(value, "value");
        if (value.length > 1024 * 1024) {
            throw new IllegalArgumentException("AAD must not exceed 1 MiB");
        }
        return value.length == 0 ? EMPTY : new AAD(value.clone());
    }

    public static AAD ofUtf8(String value) {
        Objects.requireNonNull(value, "value");
        return of(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static AAD empty() {
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
        return other instanceof AAD aad && MessageDigest.isEqual(value, aad.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "AAD[length=" + value.length + "]";
    }
}
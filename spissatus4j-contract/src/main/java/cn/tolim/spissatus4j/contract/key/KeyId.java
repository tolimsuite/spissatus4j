package cn.tolim.spissatus4j.contract.key;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Opaque, stable key identifier. It is not secret, but is deliberately not a
 * natural-language name, so accidental key substitution is easier to detect.
 */
public final class KeyId implements Comparable<KeyId> {

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    private final String value;

    private KeyId(String value) {
        this.value = value;
    }

    public static KeyId of(String value) {
        String candidate = Objects.requireNonNull(value, "value").trim();
        if (!VALID.matcher(candidate).matches()) {
            throw new IllegalArgumentException("Invalid key identifier");
        }
        return new KeyId(candidate);
    }

    public String value() {
        return value;
    }

    @Override
    public int compareTo(KeyId other) {
        return value.compareTo(other.value);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof KeyId keyId && value.equals(keyId.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }
}
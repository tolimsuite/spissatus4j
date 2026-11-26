package cn.tolim.spissatus4j.contract.key;

/** Monotonically increasing version of a logical key. */
public record KeyVersion(long value) implements Comparable<KeyVersion> {

    public KeyVersion {
        if (value < 1) {
            throw new IllegalArgumentException("Key version must be positive");
        }
    }

    public static KeyVersion first() {
        return new KeyVersion(1);
    }

    public static KeyVersion of(long value) {
        return new KeyVersion(value);
    }

    public KeyVersion next() {
        return new KeyVersion(Math.addExact(value, 1));
    }

    @Override
    public int compareTo(KeyVersion other) {
        return Long.compare(value, other.value);
    }

    @Override
    public String toString() {
        return Long.toString(value);
    }
}
package cn.tolim.spissatus4j.contract.runtime;

/**
 * Constant-time comparisons for authentication tags, MACs, digests and other
 * secret-derived values. Implementations must not return early on the first
 * differing byte.
 */
public interface ConstantTimeComparator {

    boolean equals(byte[] left, byte[] right);

    boolean equals(char[] left, char[] right);

    default boolean equals(String left, String right) {
        if (left == null || right == null) {
            return left == right;
        }
        return equals(left.toCharArray(), right.toCharArray());
    }
}
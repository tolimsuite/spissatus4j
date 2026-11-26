package cn.tolim.spissatus4j.core.runtime;

import cn.tolim.spissatus4j.contract.runtime.ConstantTimeComparator;
import java.security.MessageDigest;

/** Constant-time comparison implementation with no early return on mismatch. */
public final class DefaultConstantTimeComparator implements ConstantTimeComparator {

    @Override
    public boolean equals(byte[] left, byte[] right) {
        if (left == null || right == null) {
            return left == right;
        }
        return MessageDigest.isEqual(left, right);
    }

    @Override
    public boolean equals(char[] left, char[] right) {
        if (left == null || right == null) {
            return left == right;
        }
        int length = Math.max(left.length, right.length);
        int difference = left.length ^ right.length;
        for (int i = 0; i < length; i++) {
            char a = i < left.length ? left[i] : 0;
            char b = i < right.length ? right[i] : 0;
            difference |= a ^ b;
        }
        return difference == 0;
    }
}
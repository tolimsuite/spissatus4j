package cn.tolim.spissatus4j.core.testkit;

import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.SplittableRandom;
import java.util.function.Supplier;

/** Dependency-free helpers shared by module tests. */
public final class TestSupport {

    private TestSupport() {
    }

    public static byte[] hex(String value) {
        return HexFormat.of().parseHex(value.replace(" ", ""));
    }

    public static String hex(byte[] value) {
        return HexFormat.of().formatHex(value);
    }

    public static byte[] randomBytes(long seed, int length) {
        byte[] result = new byte[length];
        new SplittableRandom(seed).nextBytes(result);
        return result;
    }

    public static byte[] corrupt(byte[] value, int index) {
        Objects.requireNonNull(value, "value");
        byte[] copy = value.clone();
        copy[index] ^= 0x01;
        return copy;
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static <T extends SpissatusException> T assertThrows(Class<T> type, Supplier<?> action) {
        try {
            action.get();
            throw new AssertionError("Expected " + type.getSimpleName() + " but nothing was thrown");
        } catch (SpissatusException e) {
            if (!type.isInstance(e)) {
                throw new AssertionError("Expected " + type.getSimpleName() + " but got "
                        + e.getClass().getSimpleName(), e);
            }
            return type.cast(e);
        }
    }
}
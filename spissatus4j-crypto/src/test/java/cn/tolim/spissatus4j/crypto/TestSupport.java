package cn.tolim.spissatus4j.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Shared deterministic test data and helpers. */
public final class TestSupport {

    private TestSupport() {
    }

    public static byte[] bytes(int length, int seed) {
        byte[] value = new byte[length];
        int state = seed == 0 ? 0x12345678 : seed;
        for (int i = 0; i < length; i++) {
            state = state * 1103515245 + 12345;
            value[i] = (byte) (state >>> 16);
        }
        return value;
    }

    public static byte[] hex(String value) {
        if (value.length() % 2 != 0) {
            throw new IllegalArgumentException("Odd hex length");
        }
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) ((Character.digit(value.charAt(i * 2), 16) << 4)
                    | Character.digit(value.charAt(i * 2 + 1), 16));
        }
        return result;
    }

    public static SecretKey aesKey(int bytes, int seed) {
        return new SecretKeySpec(bytes(bytes, seed), "AES");
    }

    public static SecretKey chaChaKey(int seed) {
        return new SecretKeySpec(bytes(32, seed), "ChaCha20");
    }

    public static KeyPair rsaKeyPair(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair ecKeyPair(String curve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair edKeyPair(String algorithm) {
        try {
            return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }
}

package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;

/** Package-private validation and encoding helpers shared by the JCA engines. */
final class CryptoSupport {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CryptoSupport() {
    }

    /**
     * Returns a defensive copy of the AES key bytes, enforcing the allowed AES
     * key sizes (128/192/256 bits).
     */
    public static byte[] requireAesKey(SecretKey key, AlgorithmId algorithm) {
        byte[] encoded = requireKeyBytes(key, algorithm);
        int length = encoded.length;
        if (length != 16 && length != 24 && length != 32) {
            if (length * 8 < 128) {
                Arrays.fill(encoded, (byte) 0);
                throw new CryptoException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "AES key must be at least 128 bits");
            }
            Arrays.fill(encoded, (byte) 0);
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "AES key must be 16, 24 or 32 bytes");
        }
        return encoded;
    }

    /** Returns a defensive copy of the ChaCha20 key bytes (256 bits exactly). */
    public static byte[] requireChaChaKey(SecretKey key, AlgorithmId algorithm) {
        byte[] encoded = requireKeyBytes(key, algorithm);
        if (encoded.length != 32) {
            Arrays.fill(encoded, (byte) 0);
            if (encoded.length * 8 < 256) {
                throw new CryptoException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "ChaCha20-Poly1305 key must be 256 bits");
            }
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "ChaCha20-Poly1305 key must be 32 bytes");
        }
        return encoded;
    }

    private static byte[] requireKeyBytes(SecretKey key, AlgorithmId algorithm) {
        Objects.requireNonNull(key, "key");
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Key material is not exportable for " + algorithm.id());
        }
        return encoded;
    }

    /** Validates a nonce length, returning a copy of its bytes. */
    public static byte[] requireNonce(Nonce nonce, int expectedLength, AlgorithmId algorithm) {
        Objects.requireNonNull(nonce, "nonce");
        byte[] bytes = nonce.asBytes();
        if (bytes.length != expectedLength) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Nonce must be " + expectedLength + " bytes for " + algorithm.id());
        }
        return bytes;
    }

    /** Maps a provider failure to a contract exception without leaking material. */
    public static CryptoException providerFailure(String operation, GeneralSecurityException cause) {
        return new CryptoException(ErrorCode.PROVIDER_FAILURE, operation + " failed", cause);
    }

    public static byte[] hex(String value) {
        if (value.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hex string");
            }
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
    }

    public static String toHex(byte[] value) {
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte b : value) {
            builder.append(HEX[(b >> 4) & 0x0f]).append(HEX[b & 0x0f]);
        }
        return builder.toString();
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}

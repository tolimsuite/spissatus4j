package cn.tolim.spissatus4j.gm.internal;

import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.util.Arrays;
import javax.crypto.SecretKey;

/** Shared SM4 key, nonce, AAD and buffer validation. */
public final class Sm4Keys {

    public static final int KEY_LENGTH = 16;

    private Sm4Keys() {
    }

    /** Returns a private copy of the 128-bit key, or a generic parameter error. */
    public static byte[] requireKey(SecretKey key) {
        if (key == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A secret key is required");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length != KEY_LENGTH) {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "SM4 requires a 128-bit key");
        }
        return encoded;
    }

    /** Returns a private copy of the nonce, enforcing the expected length. */
    public static byte[] requireNonce(Nonce nonce, int expectedLength) {
        if (nonce == null) {
            throw new CryptoException(ErrorCode.NONCE_INVALID, "A nonce is required");
        }
        byte[] bytes = nonce.asBytes();
        if (bytes.length != expectedLength) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Nonce must be " + expectedLength + " bytes");
        }
        return bytes;
    }

    /** Returns a private copy of the additional authenticated data. */
    public static byte[] requireAad(AAD aad) {
        if (aad == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "AAD is required");
        }
        return aad.asBytes();
    }

    /** Returns a private copy of a required input buffer. */
    public static byte[] requireBytes(byte[] value, String fieldName) {
        if (value == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, fieldName + " is required");
        }
        return value.clone();
    }
}
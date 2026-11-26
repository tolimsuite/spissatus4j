package cn.tolim.spissatus4j.gm.sm3;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/** HMAC-SM3 with a 256-bit tag and constant-time verification. */
public final class Sm3Mac implements MacFunction {

    public static final int TAG_LENGTH = 32;

    private static final int STREAM_BUFFER_SIZE = 8192;

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.HMAC_SM3;
    }

    @Override
    public int tagLength() {
        return TAG_LENGTH;
    }

    @Override
    public byte[] compute(SecretKey key, byte[] data) {
        byte[] keyBytes = requireKeyBytes(key);
        try {
            if (data == null) {
                throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Data is required");
            }
            HMac mac = new HMac(new SM3Digest());
            mac.init(new KeyParameter(keyBytes));
            mac.update(data, 0, data.length);
            byte[] tag = new byte[TAG_LENGTH];
            mac.doFinal(tag, 0);
            return tag;
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    @Override
    public byte[] compute(SecretKey key, InputStream input) throws IOException {
        if (input == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Input stream is required");
        }
        byte[] keyBytes = requireKeyBytes(key);
        try {
            HMac mac = new HMac(new SM3Digest());
            mac.init(new KeyParameter(keyBytes));
            byte[] buffer = new byte[STREAM_BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) != -1) {
                mac.update(buffer, 0, read);
            }
            byte[] tag = new byte[TAG_LENGTH];
            mac.doFinal(tag, 0);
            return tag;
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    @Override
    public boolean verify(SecretKey key, byte[] data, byte[] expectedTag) {
        if (expectedTag == null || expectedTag.length != TAG_LENGTH) {
            return false;
        }
        byte[] actualTag = compute(key, data);
        try {
            return MessageDigest.isEqual(actualTag, expectedTag);
        } finally {
            Arrays.fill(actualTag, (byte) 0);
        }
    }

    private static byte[] requireKeyBytes(SecretKey key) {
        if (key == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A secret key is required");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0) {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "HMAC-SM3 requires a non-empty key");
        }
        return encoded;
    }
}
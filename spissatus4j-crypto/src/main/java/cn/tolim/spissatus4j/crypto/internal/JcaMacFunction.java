package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/** JCA HMAC function with constant-time verification. */
final class JcaMacFunction implements MacFunction {

    private static final int BUFFER_SIZE = 8192;

    private final AlgorithmId algorithm;
    private final String jcaName;
    private final int tagLength;

    JcaMacFunction(AlgorithmId algorithm, String jcaName) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName");
        try {
            this.tagLength = Mac.getInstance(jcaName).getMacLength();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "MAC algorithm unavailable: " + algorithm.id(), e);
        }
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public int tagLength() {
        return tagLength;
    }

    @Override
    public byte[] compute(SecretKey key, byte[] data) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(data, "data");
        try {
            Mac mac = newMac(key);
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "MAC computation failed", e);
        }
    }

    @Override
    public byte[] compute(SecretKey key, InputStream input) throws IOException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(input, "input");
        try {
            Mac mac = newMac(key);
            byte[] buffer = new byte[BUFFER_SIZE];
            try {
                int read;
                while ((read = input.read(buffer)) != -1) {
                    if (read > 0) {
                        mac.update(buffer, 0, read);
                    }
                }
                return mac.doFinal();
            } finally {
                CryptoSupport.wipe(buffer);
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "MAC computation failed", e);
        }
    }

    @Override
    public boolean verify(SecretKey key, byte[] data, byte[] expectedTag) {
        Objects.requireNonNull(expectedTag, "expectedTag");
        byte[] actual = compute(key, data);
        try {
            return MessageDigest.isEqual(actual, expectedTag);
        } finally {
            CryptoSupport.wipe(actual);
        }
    }

    private Mac newMac(SecretKey key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(jcaName);
        mac.init(key);
        return mac;
    }
}

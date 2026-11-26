package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;

/** MessageDigest-backed hash function with bounded-buffer streaming support. */
final class JcaHashFunction implements HashFunction {

    private static final int BUFFER_SIZE = 8192;

    private final AlgorithmId algorithm;
    private final String jcaName;
    private final int digestLength;

    JcaHashFunction(AlgorithmId algorithm, String jcaName) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName");
        try {
            this.digestLength = MessageDigest.getInstance(jcaName).getDigestLength();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "Digest algorithm unavailable: " + algorithm.id(), e);
        }
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public int digestLength() {
        return digestLength;
    }

    @Override
    public byte[] digest(byte[] data) {
        Objects.requireNonNull(data, "data");
        return newDigest().digest(data);
    }

    @Override
    public byte[] digest(InputStream input) throws IOException {
        Objects.requireNonNull(input, "input");
        MessageDigest digest = newDigest();
        byte[] buffer = new byte[BUFFER_SIZE];
        try {
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return digest.digest();
        } finally {
            CryptoSupport.wipe(buffer);
        }
    }

    private MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance(jcaName);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "Digest algorithm unavailable: " + algorithm.id(), e);
        }
    }
}

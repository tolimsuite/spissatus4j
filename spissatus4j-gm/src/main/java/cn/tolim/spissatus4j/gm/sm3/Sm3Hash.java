package cn.tolim.spissatus4j.gm.sm3;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.digests.SM3Digest;

/** GB/T 32905 SM3 digest (256-bit output). */
public final class Sm3Hash implements HashFunction {

    public static final int DIGEST_LENGTH = 32;

    private static final int STREAM_BUFFER_SIZE = 8192;

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.SM3;
    }

    @Override
    public int digestLength() {
        return DIGEST_LENGTH;
    }

    @Override
    public byte[] digest(byte[] data) {
        if (data == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Data is required");
        }
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] output = new byte[DIGEST_LENGTH];
        digest.doFinal(output, 0);
        return output;
    }

    @Override
    public byte[] digest(InputStream input) throws IOException {
        if (input == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Input stream is required");
        }
        SM3Digest digest = new SM3Digest();
        byte[] buffer = new byte[STREAM_BUFFER_SIZE];
        int read;
        while ((read = input.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        byte[] output = new byte[DIGEST_LENGTH];
        digest.doFinal(output, 0);
        return output;
    }
}
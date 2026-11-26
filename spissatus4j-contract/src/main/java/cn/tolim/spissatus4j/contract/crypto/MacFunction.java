package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.io.IOException;
import java.io.InputStream;
import javax.crypto.SecretKey;

/** Message authentication function with constant-time verification. */
public interface MacFunction {

    AlgorithmId algorithm();

    int tagLength();

    byte[] compute(SecretKey key, byte[] data);

    byte[] compute(SecretKey key, InputStream input) throws IOException;

    boolean verify(SecretKey key, byte[] data, byte[] expectedTag);
}
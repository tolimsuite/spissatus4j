package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.io.IOException;
import java.io.InputStream;

/** Stateless digest function. */
public interface HashFunction {

    AlgorithmId algorithm();

    int digestLength();

    byte[] digest(byte[] data);

    byte[] digest(InputStream input) throws IOException;
}
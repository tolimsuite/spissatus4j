package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Digital signature engine. Private keys never leave the key manager. */
public interface SignatureFunction {

    AlgorithmId algorithm();

    byte[] sign(PrivateKey privateKey, byte[] message);

    default byte[] sign(PrivateKey privateKey, InputStream message) throws IOException {
        return sign(privateKey, message.readAllBytes());
    }

    boolean verify(PublicKey publicKey, byte[] message, byte[] signature);
}
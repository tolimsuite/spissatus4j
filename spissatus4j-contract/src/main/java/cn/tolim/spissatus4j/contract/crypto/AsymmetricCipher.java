package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Public-key encryption engine (RSA-OAEP, ECIES, SM2). */
public interface AsymmetricCipher {

    AlgorithmId algorithm();

    byte[] encrypt(PublicKey publicKey, byte[] plaintext);

    byte[] decrypt(PrivateKey privateKey, byte[] ciphertext);
}
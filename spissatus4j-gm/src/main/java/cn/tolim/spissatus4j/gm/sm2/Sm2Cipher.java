package cn.tolim.spissatus4j.gm.sm2;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.gm.internal.BcKeyConversion;
import cn.tolim.spissatus4j.gm.internal.Sm2Operations;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * SM2 public-key encryption (GB/T 32918) with SM3 and C1C3C2 ordering.
 * Only keys on {@code sm2p256v1} are accepted.
 */
public final class Sm2Cipher implements AsymmetricCipher {

    private final SecureRandom random;

    public Sm2Cipher() {
        this.random = new SecureRandom();
    }

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.SM2;
    }

    @Override
    public byte[] encrypt(PublicKey publicKey, byte[] plaintext) {
        return Sm2Operations.encrypt(BcKeyConversion.toPublicKeyParameters(publicKey), plaintext, random);
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) {
        return Sm2Operations.decrypt(BcKeyConversion.toPrivateKeyParameters(privateKey), ciphertext);
    }
}
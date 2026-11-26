package cn.tolim.spissatus4j.gm.sm2;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;
import javax.crypto.SecretKey;

/**
 * Wraps data encryption keys under an SM2 key-encryption key. Wrapping is an
 * SM2 encryption of the DEK to the KEK public key; unwrapping is the matching
 * SM2 decryption.
 */
public final class Sm2KeyWrapper implements KeyWrapper {

    public static final String WRAPPER_ID = "sm2";

    private static final Set<AlgorithmId> ALGORITHMS = Set.of(AlgorithmId.SM2);

    private final Sm2Cipher cipher;

    public Sm2KeyWrapper() {
        this.cipher = new Sm2Cipher();
    }

    @Override
    public String wrapperId() {
        return WRAPPER_ID;
    }

    @Override
    public Set<AlgorithmId> algorithms() {
        return ALGORITHMS;
    }

    @Override
    public byte[] wrap(PublicKey kek, byte[] dek) {
        return cipher.encrypt(kek, dek);
    }

    @Override
    public byte[] unwrap(PrivateKey kek, byte[] wrappedDek) {
        return cipher.decrypt(kek, wrappedDek);
    }
}